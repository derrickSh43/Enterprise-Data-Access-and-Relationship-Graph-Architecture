"""Action / Workflow Layer: controlled verbs, not arbitrary tool execution.

Every action declares:
- the cloud authority its access path must confer,
- the resource kinds and provider it applies to ("*" = any) - requests
  targeting an incompatible object are rejected before policy runs,
- a strict typed input schema (unknown fields rejected, lengths bounded),
- the approved output keys (anything else a handler returns is stripped),
- risk, blast radius, rollback, and an execution timeout.

High-risk and write actions execute inside the controlled runner: a separate
OS process that receives the brokered credentials, is killed on timeout, and
returns only approved outputs. Credentials never reach the caller.
"""

from dataclasses import dataclass, field
from typing import Callable

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy.orm import Session

from . import broker as broker_mod
from . import runner
from .models import Grant


class ActionError(Exception):
    pass


# --- Typed input schemas (item: strict validation, extra="forbid") -----------
class _NoInputs(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OpenTicketInputs(_NoInputs):
    summary: str = Field(min_length=3, max_length=500)


class RotateSecretInputs(_NoInputs):
    pass


class DisableAccessInputs(_NoInputs):
    reason: str = Field(min_length=3, max_length=500)


@dataclass(frozen=True)
class ActionDef:
    name: str
    description: str
    cloud_action: str              # authority the access path must confer
    read_only: bool
    risk: str                      # low | medium | high
    blast_radius: str
    resource_kinds: tuple          # object-graph kinds this action applies to; ("*",) = any
    provider: str = "aws"
    input_model: type[BaseModel] = _NoInputs
    allowed_outputs: tuple = ()
    rollback: str = "n/a (read-only)"
    timeout_seconds: int = 30
    handler: Callable[..., tuple[dict, list[dict]]] = field(default=None, repr=False)

    @property
    def handler_path(self) -> str:
        return f"{self.handler.__module__}.{self.handler.__name__}"


# --- Handlers: (credentials, resource, inputs) -> (outputs, api_calls) ------
# Importable top-level functions so the controlled runner can execute them in
# a spawned process. Credentials arrive from the broker vault, never the DB.


def _h_view_asset(credentials: dict, resource: str, inputs: dict):
    return {"viewed": resource}, []


def _h_inspect_instance(credentials: dict, resource: str, inputs: dict):
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


def _h_open_ticket(credentials: dict, resource: str, inputs: dict):
    ticket_id = f"TKT-{abs(hash((resource, inputs.get('summary', '')))) % 10000:04d}"
    return {"ticket_id": ticket_id, "summary": inputs.get("summary", "")}, [
        {"service": "ticketing", "call": "CreateTicket", "params": {"resource": resource}}
    ]


def _h_rotate_secret(credentials: dict, resource: str, inputs: dict):
    api_calls = [
        {"service": "secretsmanager", "call": "RotateSecret", "params": {"SecretId": resource}}
    ]
    return {"secret": resource, "rotation": "initiated", "executed_via": "controlled_runner"}, api_calls


def _h_disable_access(credentials: dict, resource: str, inputs: dict):
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
            resource_kinds=("*",),
            allowed_outputs=("viewed",),
            handler=_h_view_asset,
        ),
        ActionDef(
            name="inspect_instance",
            description="Read-only investigation of an EC2 instance (incident workflow).",
            cloud_action="ec2:DescribeInstances",
            read_only=True,
            risk="low",
            blast_radius="none (read)",
            resource_kinds=("ec2_instance",),
            allowed_outputs=("instance", "state", "security_groups", "launch_time", "mode"),
            handler=_h_inspect_instance,
        ),
        ActionDef(
            name="open_ticket",
            description="Open a tracking ticket linked to an object.",
            cloud_action="ticketing:CreateTicket",
            read_only=False,
            risk="low",
            blast_radius="one ticket record",
            resource_kinds=("*",),
            provider="ticketing",
            input_model=OpenTicketInputs,
            allowed_outputs=("ticket_id", "summary"),
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
            resource_kinds=("secret",),
            input_model=RotateSecretInputs,
            allowed_outputs=("secret", "rotation", "executed_via"),
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
            resource_kinds=("identity", "user"),
            provider="iam",
            input_model=DisableAccessInputs,
            allowed_outputs=("target", "access", "executed_via"),
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


def check_compatibility(action: ActionDef, resource_kind: str | None) -> None:
    """Reject actions that do not apply to the target's kind. Unmodeled
    resources only qualify for kind-agnostic actions."""
    if "*" in action.resource_kinds:
        return
    if resource_kind is None:
        raise ActionError(
            f"action {action.name!r} requires resource kind {action.resource_kinds} "
            "but the target is not modeled in the object graph"
        )
    if resource_kind not in action.resource_kinds:
        raise ActionError(
            f"action {action.name!r} does not apply to resource kind {resource_kind!r} "
            f"(supports: {', '.join(action.resource_kinds)})"
        )


def validate_inputs(action: ActionDef, inputs: dict | None) -> dict:
    try:
        return action.input_model(**(inputs or {})).model_dump()
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc']) or 'inputs'}: {e['msg']}" for e in exc.errors()
        )
        raise ActionError(f"invalid inputs for {action.name!r}: {problems}")


def execute(
    db: Session,
    *,
    action: ActionDef,
    grant: Grant,
    resource: str,
    inputs: dict | None = None,
    resource_kind: str | None = None,
) -> dict:
    """Validate compatibility, inputs, and the grant, then run the handler -
    in-process for low-risk reads, inside the controlled runner otherwise."""
    check_compatibility(action, resource_kind)
    validated = validate_inputs(action, inputs)
    broker_mod.validate_grant(grant, action=action.cloud_action, resource=resource)
    credentials = broker_mod.fetch_credentials(grant)

    controlled = action.risk == "high" or not action.read_only
    if controlled:
        try:
            outputs, api_calls = runner.run_controlled(
                action.handler_path,
                credentials=credentials,
                resource=resource,
                inputs=validated,
                allowed_outputs=action.allowed_outputs,
                timeout_seconds=action.timeout_seconds,
            )
        except runner.RunnerError as exc:
            raise ActionError(f"controlled runner: {exc}")
    else:
        raw_outputs, api_calls = action.handler(credentials, resource, validated)
        outputs = {k: v for k, v in raw_outputs.items() if k in action.allowed_outputs}

    return {
        "action": action.name,
        "resource": resource,
        "execution_mode": "controlled_runner" if controlled else "direct",
        "outputs": outputs,
        "api_calls": api_calls,
        "rollback": action.rollback,
        "blast_radius": action.blast_radius,
    }
