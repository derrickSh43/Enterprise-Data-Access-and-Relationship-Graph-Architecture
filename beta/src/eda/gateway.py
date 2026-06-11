"""Gateway: orchestrates the request flow.

    authenticate -> map identity to graph principal -> check action/resource
    compatibility -> resolve access path -> evaluate policy -> consume
    approval -> broker grant -> scoped context -> execute action -> audit

Identity comes from the configured IdentityProvider (OIDC in production, the
HMAC dev provider for tests/local demos) and must map to an existing access
graph principal - unknown identities fail closed before any policy or graph
work happens.

Approvals are their own authorization decision: approving requires a proven
access path showing the approver holds the server-derived
"approval:<action>" capability for the target resource (preserved as
evidence), is not the requester, and acts before the approval expires. Each
approval is bound to the exact request (subject, action, resource, inputs
hash) and consumed atomically exactly once.

Every terminal outcome (denied, approval_required, allowed, error) writes one
audit record carrying the entire evidence chain for that correlation ID.
"""

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import update
from sqlalchemy.orm import Session

from . import access_graph, actions, audit, broker, identity, objects, policy
from .config import settings
from .identity_providers import get_identity_provider, map_principal
from .models import AccessNode, Approval, utcnow


def _inputs_hash(inputs: dict | None) -> str:
    canonical = json.dumps(inputs or {}, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _aware(ts: datetime | None) -> datetime | None:
    if ts is not None and ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts


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
            tenant_id=session.tenant,
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
        "tenant_id": session.tenant,
    }

    # 2. Action must exist in the closed registry and apply to this resource
    try:
        action = actions.get_action(action_name)
        target_object = objects.get_object_by_name(db, resource)
        resource_kind = target_object.kind if target_object else None
        actions.check_compatibility(action, resource_kind)
        validated_inputs = actions.validate_inputs(action, inputs)
    except actions.ActionError as exc:
        return finish("denied", error=str(exc), **base_audit)

    # 3. Access Graph: prove an authority path for the action's cloud
    # authority, confined to the session's tenant
    path = access_graph.resolve_path(
        db, principal.name, action.cloud_action, resource, tenant=session.tenant
    )
    trace["stages"]["access_path"] = path.as_json() if path else None

    # 4. Approval lookup: an approval is valid only for the exact request it
    # was created for (subject, action, resource, inputs), within its TTL,
    # within the same tenant, and only while still un-consumed.
    approval_record = db.get(Approval, approval_id) if approval_id else None
    approval_valid = (
        approval_record is not None
        and approval_record.status == "approved"
        and approval_record.subject == principal.name
        and approval_record.action == action_name
        and approval_record.resource == resource
        and approval_record.inputs_hash == _inputs_hash(validated_inputs)
        and approval_record.tenant_id == session.tenant
        and datetime.now(timezone.utc) <= _aware(approval_record.expires_at)
    )

    # 5. Policy Engine
    policy_input = {
        "subject": principal.name,
        "session": {"mfa": session.mfa, "risk_score": session.risk_score},
        "action": {"name": action.name, "cloud_action": action.cloud_action,
                   "read_only": action.read_only, "risk": action.risk},
        "resource": {"name": resource, **(dict(target_object.attrs) if target_object else {})},
        "access_path_exists": path is not None,
        "justification": justification,
        "approval_present": approval_valid,
    }
    try:
        decision = policy.evaluate(db, policy_input)
    except policy.PolicyError as exc:
        return finish("denied", error=f"policy integrity: {exc}", **base_audit)
    trace["stages"]["policy"] = decision.as_json()
    audit_policy = {
        "access_path": path.as_json() if path else None,
        "policy_input": policy_input,
        "policy_decision": decision.as_json(),
        "policy_version": decision.policy_version,
        "approval": (
            {"approval_id": approval_record.id, "status": approval_record.status,
             "approver": approval_record.approver,
             "approver_path": approval_record.approver_path}
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
            inputs_hash=_inputs_hash(validated_inputs),
            required_capability=f"approval:{action_name}",  # server-derived, never client input
            justification=justification,
            expires_at=utcnow() + timedelta(seconds=settings.approval_ttl_seconds),
            correlation_id=correlation_id,
            tenant_id=session.tenant,
        )
        db.add(pending)
        db.flush()
        trace["stages"]["approval"] = {
            "approval_id": pending.id,
            "status": "pending",
            "required_capability": pending.required_capability,
            "expires_at": pending.expires_at.isoformat(),
            "resubmit_with": "approval_id once approved",
        }
        return finish("approval_required", **base_audit, **audit_policy)

    # 5b. Consume the approval atomically: exactly one request can spend it.
    if approval_valid:
        consumed = db.execute(
            update(Approval)
            .where(Approval.id == approval_record.id, Approval.status == "approved")
            .values(status="consumed", consumed_at=datetime.now(timezone.utc))
        )
        if consumed.rowcount != 1:
            return finish(
                "denied",
                error="approval already consumed by a concurrent request",
                **base_audit, **audit_policy,
            )

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
        tenant_id=session.tenant,
    )
    trace["stages"]["grant"] = broker.redacted(grant)

    # 7. Object Graph: scoped context, only now, with per-node disclosure
    context = objects.scoped_context(db, grant=grant, resource=resource)
    trace["stages"]["context"] = context

    # 8. Action Layer (controlled runner for writes/high risk)
    try:
        result = actions.execute(
            db, action=action, grant=grant, resource=resource,
            inputs=validated_inputs, resource_kind=resource_kind,
        )
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


def decide_approval(
    db: Session, approval_id: str, *, approver: AccessNode, approve: bool
) -> Approval:
    """Approval is a separate authorization decision. The approver must:
    - not be the requester (self-approval rejected),
    - hold a proven access path conferring the approval's server-derived
      capability for the target resource (path preserved as evidence),
    - decide before the approval expires.
    """
    record = db.get(Approval, approval_id)
    if record is None:
        raise ValueError("unknown approval")
    if record.status != "pending":
        raise ValueError(f"approval already {record.status}")
    if approver.name == record.subject:
        raise ValueError("self-approval is not permitted")
    if datetime.now(timezone.utc) > _aware(record.expires_at):
        raise ValueError("approval request expired")

    approver_path = access_graph.capability_path(
        db, approver.name, record.required_capability, record.resource,
        tenant=record.tenant_id,
    )
    if approver_path is None:
        raise PermissionError(
            f"approver holds no access path conferring "
            f"{record.required_capability!r} for {record.resource!r}"
        )

    record.status = "approved" if approve else "rejected"
    record.approver = approver.name
    record.approver_path = approver_path.as_json()
    record.decided_at = datetime.now(timezone.utc)
    audit.append(
        db,
        correlation_id=record.correlation_id,
        subject=approver.name,
        session_id="-",
        event="approval_decision",
        action=record.action,
        target=record.resource,
        access_path=approver_path.as_json(),
        approval={"approval_id": record.id, "status": record.status,
                  "approver": approver.name,
                  "required_capability": record.required_capability},
        result=record.status,
        tenant_id=record.tenant_id,
    )
    db.commit()
    return record
