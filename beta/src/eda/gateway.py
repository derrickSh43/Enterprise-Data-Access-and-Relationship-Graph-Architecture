"""Gateway: orchestrates the request flow.

    authenticate -> map identity to graph principal -> resolve access path
    -> evaluate policy -> broker grant -> scoped context -> execute action
    -> audit the full chain

Identity comes from the configured IdentityProvider (OIDC in production, the
HMAC dev provider for tests/local demos) and must map to an existing access
graph principal - unknown identities fail closed before any policy or graph
work happens.

Every terminal outcome (denied, approval_required, allowed, error) writes one
audit record carrying the entire evidence chain for that correlation ID.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from . import access_graph, actions, audit, broker, identity, objects, policy
from .identity_providers import get_identity_provider, map_principal
from .models import Approval, ObjectNode
from sqlalchemy import select


def _resource_attrs(db: Session, resource: str) -> dict:
    node = db.scalar(select(ObjectNode).where(ObjectNode.name == resource))
    return dict(node.attrs) if node else {}


def handle_request(
    db: Session,
    *,
    bearer_token: str,
    action_name: str,
    resource: str,
    inputs: dict | None = None,
    justification: dict | None = None,
    approval_id: str | None = None,
) -> dict:
    correlation_id = uuid.uuid4().hex
    justification = justification or {}
    trace: dict = {"correlation_id": correlation_id, "stages": {}}

    def finish(result: str, *, error: str | None = None, **audit_fields) -> dict:
        audit.append(
            db,
            correlation_id=correlation_id,
            result=result,
            error=error,
            **audit_fields,
        )
        db.commit()
        trace["outcome"] = result
        if error:
            trace["error"] = error
        return trace

    # 1. Identity: validate the bearer token with the configured provider
    try:
        session = get_identity_provider().verify(bearer_token)
    except identity.InvalidSession as exc:
        return finish(
            "denied",
            error=f"identity: {exc}",
            subject="unknown",
            session_id="-",
            event="request",
            action=action_name,
            target=resource,
        )

    # 1b. Map issuer+subject -> tenant + external ID -> existing graph
    # principal. No mapped principal means deny, before anything else runs.
    principal = map_principal(db, session)
    if principal is None:
        return finish(
            "denied",
            error="identity: no mapped graph principal for this identity (fail closed)",
            subject=session.external_id or session.subject,
            session_id=session.session_id,
            event="request",
            action=action_name,
            target=resource,
        )
    trace["stages"]["identity"] = {
        "subject": principal.name,
        "external_id": session.external_id,
        "issuer": session.issuer,
        "tenant": session.tenant,
        "mfa": session.mfa,
        "risk_score": session.risk_score,
    }
    base_audit = {
        "subject": principal.name,
        "session_id": session.session_id,
        "event": "request",
        "action": action_name,
        "target": resource,
    }

    # 2. Action must exist in the closed registry
    try:
        action = actions.get_action(action_name)
    except actions.ActionError as exc:
        return finish("denied", error=str(exc), **base_audit)

    # 3. Access Graph: prove an authority path for the action's cloud authority
    path = access_graph.resolve_path(db, principal.name, action.cloud_action, resource)
    trace["stages"]["access_path"] = path.as_json() if path else None

    # 4. Approval lookup (if resubmitting with one)
    approval_record = db.get(Approval, approval_id) if approval_id else None
    approval_valid = (
        approval_record is not None
        and approval_record.status == "approved"
        and approval_record.subject == principal.name
        and approval_record.action == action_name
        and approval_record.resource == resource
    )

    # 5. Policy Engine
    policy_input = {
        "subject": principal.name,
        "session": {"mfa": session.mfa, "risk_score": session.risk_score},
        "action": {"name": action.name, "cloud_action": action.cloud_action,
                   "read_only": action.read_only, "risk": action.risk},
        "resource": {"name": resource, **_resource_attrs(db, resource)},
        "access_path_exists": path is not None,
        "justification": justification,
        "approval_present": approval_valid,
    }
    decision = policy.evaluate(db, policy_input)
    trace["stages"]["policy"] = decision.as_json()
    audit_policy = {
        "access_path": path.as_json() if path else None,
        "policy_input": policy_input,
        "policy_decision": decision.as_json(),
        "policy_version": decision.policy_version,
        "approval": (
            {"approval_id": approval_record.id, "status": approval_record.status,
             "approver": approval_record.approver}
            if approval_record
            else None
        ),
    }

    if decision.decision == "denied":
        return finish("denied", error=decision.reason, **base_audit, **audit_policy)

    if decision.decision == "approval_required":
        pending = Approval(
            subject=principal.name,
            action=action_name,
            resource=resource,
            justification=justification,
            correlation_id=correlation_id,
        )
        db.add(pending)
        db.flush()
        trace["stages"]["approval"] = {
            "approval_id": pending.id,
            "status": "pending",
            "resubmit_with": "approval_id once approved",
        }
        return finish("approval_required", **base_audit, **audit_policy)

    # 6. Authority Broker: temporary scoped grant
    grant = broker.issue_grant(
        db,
        subject=principal.name,
        action=action.cloud_action,
        resource=resource,
        obligations=decision.obligations,
        session_tags={"session_id": session.session_id, "correlation_id": correlation_id,
                      **session.tags},
        correlation_id=correlation_id,
    )
    trace["stages"]["grant"] = broker.redacted(grant)

    # 7. Object Graph: scoped context, only now
    context = objects.scoped_context(db, grant=grant, resource=resource)
    trace["stages"]["context"] = context

    # 8. Action Layer
    try:
        result = actions.execute(db, action=action, grant=grant, resource=resource, inputs=inputs)
    except (actions.ActionError, broker.GrantError) as exc:
        return finish("error", error=str(exc), **base_audit, **audit_policy,
                      grant=broker.redacted(grant))
    trace["stages"]["action_result"] = result

    # 9. Audit the full chain
    return finish(
        "allowed",
        **base_audit,
        **audit_policy,
        grant=broker.redacted(grant),
        api_calls=result["api_calls"],
        context_summary={"root": context["root"], "nodes": len(context["nodes"]),
                         "edges": len(context["edges"])},
    )


def decide_approval(db: Session, approval_id: str, *, approver: str, approve: bool) -> Approval:
    record = db.get(Approval, approval_id)
    if record is None:
        raise ValueError("unknown approval")
    if record.status != "pending":
        raise ValueError(f"approval already {record.status}")
    if approver == record.subject:
        raise ValueError("self-approval is not permitted")
    record.status = "approved" if approve else "rejected"
    record.approver = approver
    record.decided_at = datetime.now(timezone.utc)
    audit.append(
        db,
        correlation_id=record.correlation_id,
        subject=approver,
        session_id="-",
        event="approval_decision",
        action=record.action,
        target=record.resource,
        approval={"approval_id": record.id, "status": record.status, "approver": approver},
        result=record.status,
    )
    db.commit()
    return record
