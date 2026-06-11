"""Action / Workflow Layer: controlled verbs, not arbitrary tool execution.

Every action declares its required cloud authority, risk, blast radius,
rollback behavior, and whether it is read-only. High-risk actions run through
the "controlled runner": the handler executes server-side with the brokered
credentials and only outputs are returned - credentials are never handed to
the caller (human or agent).
"""

from dataclasses import dataclass, field
from typing import Callable

from sqlalchemy.orm import Session

from . import broker as broker_mod
from .models import Grant


class ActionError(Exception):
    pass


@dataclass(frozen=True)
class ActionDef:
    name: str
    description: str
    cloud_action: str          # authority the access path must confer
    read_only: bool
    risk: str                  # low | medium | high
    blast_radius: str
    required_inputs: tuple = ()
    rollback: str = "n/a (read-only)"
    handler: Callable[..., tuple[dict, list[dict]]] = field(default=None, repr=False)


# --- Handlers: mock cloud calls; each returns (outputs, api_calls) ----------


def _h_view_asset(grant: Grant, resource: str, inputs: dict):
    return {"viewed": resource}, []


def _h_inspect_instance(grant: Grant, resource: str, inputs: dict):
    api_calls = [
        {"service": "ec2", "call": "DescribeInstances", "params": {"InstanceIds": [resource]}},
        {"service": "ec2", "call": "DescribeSecurityGroups", "params": {"Filters": "instance"}},
    ]
    outputs = {
        "instance": resource,
        "state": "running",
        "security_groups": ["sg-prod-web"],
        "launch_time": "2026-05-30T08:12:00Z",
        "mode": "read_only_inspection",
    }
    return outputs, api_calls


def _h_open_ticket(grant: Grant, resource: str, inputs: dict):
    ticket_id = f"TKT-{abs(hash((resource, inputs.get('summary', '')))) % 10000:04d}"
    return {"ticket_id": ticket_id, "summary": inputs.get("summary", "")}, [
        {"service": "ticketing", "call": "CreateTicket", "params": {"resource": resource}}
    ]


def _h_rotate_secret(grant: Grant, resource: str, inputs: dict):
    api_calls = [
        {"service": "secretsmanager", "call": "RotateSecret", "params": {"SecretId": resource}}
    ]
    return {"secret": resource, "rotation": "initiated", "executed_via": "controlled_runner"}, api_calls


def _h_disable_access(grant: Grant, resource: str, inputs: dict):
    api_calls = [{"service": "iam", "call": "DeactivateAccessKey", "params": {"Target": resource}}]
    return {"target": resource, "access": "disabled", "executed_via": "controlled_runner"}, api_calls


REGISTRY: dict[str, ActionDef] = {
    a.name: a
    for a in [
        ActionDef(
            name="view_asset",
            description="View an asset and its scoped object-graph context.",
            cloud_action="ec2:DescribeInstances",
            read_only=True,
            risk="low",
            blast_radius="none (read)",
            handler=_h_view_asset,
        ),
        ActionDef(
            name="inspect_instance",
            description="Read-only investigation of an EC2 instance (incident workflow).",
            cloud_action="ec2:DescribeInstances",
            read_only=True,
            risk="low",
            blast_radius="none (read)",
            handler=_h_inspect_instance,
        ),
        ActionDef(
            name="open_ticket",
            description="Open a tracking ticket linked to an object.",
            cloud_action="ticketing:CreateTicket",
            read_only=False,
            risk="low",
            blast_radius="one ticket record",
            required_inputs=("summary",),
            rollback="close ticket",
            handler=_h_open_ticket,
        ),
        ActionDef(
            name="rotate_secret",
            description="Rotate a secret. High risk: dependent workloads must re-read it.",
            cloud_action="secretsmanager:RotateSecret",
            read_only=False,
            risk="high",
            blast_radius="all consumers of the secret",
            rollback="restore previous secret version",
            handler=_h_rotate_secret,
        ),
        ActionDef(
            name="disable_access",
            description="Disable a principal's access (containment).",
            cloud_action="iam:DeactivateAccessKey",
            read_only=False,
            risk="high",
            blast_radius="one principal's sessions",
            rollback="reactivate key",
            handler=_h_disable_access,
        ),
    ]
}


def get_action(name: str) -> ActionDef:
    action = REGISTRY.get(name)
    if action is None:
        raise ActionError(f"unknown action {name!r} - actions are a closed registry")
    return action


def execute(
    db: Session, *, action: ActionDef, grant: Grant, resource: str, inputs: dict | None = None
) -> dict:
    """Validate the grant against this exact action+resource, then run the handler."""
    inputs = inputs or {}
    missing = [k for k in action.required_inputs if k not in inputs]
    if missing:
        raise ActionError(f"missing required inputs: {missing}")

    broker_mod.validate_grant(grant, action=action.cloud_action, resource=resource)

    controlled = action.risk == "high" or not action.read_only
    outputs, api_calls = action.handler(grant, resource, inputs)
    return {
        "action": action.name,
        "resource": resource,
        "execution_mode": "controlled_runner" if controlled else "direct",
        "outputs": outputs,
        "api_calls": api_calls,
        "rollback": action.rollback,
        "blast_radius": action.blast_radius,
    }
