"""Policy Engine: deterministic, versioned evaluation.

Given subject, action, resource, access path, session state, and risk context,
should the request be honored? Combining rules (CEDAR/OPA-style semantics):

    explicit deny  >  require_approval (without valid approval)  >  allow
    default: deny ("no matching allow")

No model, no heuristics, no network: pure data-driven evaluation against a
closed set of condition keys. The active policy document lives in the DB and
is versioned; every decision records the version it was made under.
"""

import hashlib
import json
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import PolicyRecord

DEFAULT_POLICY = {
    "version": "2026-06-11.1",
    "rules": [
        {
            "id": "deny-no-access-path",
            "description": "No proven authority path means no access, ever.",
            "effect": "deny",
            "when": {"access_path_exists": False},
        },
        {
            "id": "deny-missing-mfa",
            "description": "All brokered authority requires MFA.",
            "effect": "deny",
            "when": {"session_mfa": False},
        },
        {
            "id": "deny-high-risk-session",
            "description": "Session risk score above 70 is not honored.",
            "effect": "deny",
            "when": {"session_risk_above": 70},
        },
        {
            "id": "deny-prod-without-case",
            "description": "Production access requires a case/incident ID.",
            "effect": "deny",
            "when": {"resource_environment": "production", "has_case_id": False},
        },
        {
            "id": "approval-for-writes",
            "description": "Non-read-only actions require human approval.",
            "effect": "require_approval",
            "when": {"action_read_only": False},
        },
        {
            "id": "approval-for-sensitive",
            "description": "Sensitive-classified resources require human approval.",
            "effect": "require_approval",
            "when": {"resource_classification": "sensitive"},
        },
        {
            "id": "allow-read-only",
            "description": "Read-only actions over a proven path are allowed, short TTL.",
            "effect": "allow",
            "when": {"action_read_only": True},
            "obligations": [{"type": "max_ttl_seconds", "value": 900}, {"type": "read_only"}],
        },
        {
            "id": "allow-approved-write",
            "description": "Writes are allowed once approved; executed via controlled runner.",
            "effect": "allow",
            "when": {"action_read_only": False},
            "obligations": [
                {"type": "max_ttl_seconds", "value": 300},
                {"type": "controlled_runner"},
            ],
        },
    ],
}

# Closed set of supported condition keys -> evaluator over the policy input.
_CONDITIONS = {
    "access_path_exists": lambda inp, v: inp["access_path_exists"] == v,
    "session_mfa": lambda inp, v: inp["session"]["mfa"] == v,
    "session_risk_above": lambda inp, v: inp["session"]["risk_score"] > v,
    "action_read_only": lambda inp, v: inp["action"]["read_only"] == v,
    "resource_environment": lambda inp, v: inp["resource"].get("environment") == v,
    "resource_classification": lambda inp, v: inp["resource"].get("classification") == v,
    "has_case_id": lambda inp, v: bool(inp["justification"].get("case_id")) == v,
}


@dataclass
class Decision:
    decision: str  # allowed | denied | approval_required
    policy_version: str
    matched_rules: list[dict] = field(default_factory=list)
    obligations: list[dict] = field(default_factory=list)
    reason: str = ""
    input_hash: str = ""

    def as_json(self) -> dict:
        return {
            "decision": self.decision,
            "policy_version": self.policy_version,
            "matched_rules": self.matched_rules,
            "obligations": self.obligations,
            "reason": self.reason,
            "input_hash": self.input_hash,
        }


class PolicyError(Exception):
    pass


def checksum(document: dict) -> str:
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def active_policy(db: Session) -> PolicyRecord:
    record = db.scalar(select(PolicyRecord).where(PolicyRecord.status == "active"))
    if record is None:
        record = PolicyRecord(
            version=DEFAULT_POLICY["version"],
            document=DEFAULT_POLICY,
            status="active",
            checksum=checksum(DEFAULT_POLICY),
            created_by="system",
        )
        db.add(record)
        db.flush()
    # Fail closed if the active document was edited outside the lifecycle
    # (e.g. directly in the database): the stored checksum no longer matches.
    if record.checksum != checksum(record.document):
        raise PolicyError(
            f"active policy {record.version!r} failed integrity check - "
            "document does not match its activation checksum"
        )
    return record


# ---------------------------------------------------------------------------
# Lifecycle: propose (validated draft) -> activate (audited) -> retire;
# rollback re-activates the previously active version. Direct DB edits of an
# active document fail the checksum above.
# ---------------------------------------------------------------------------
_VALID_EFFECTS = {"allow", "deny", "require_approval"}

# Synthetic inputs exercised against every proposed document so a broken rule
# (bad condition shape, evaluator crash) is caught before activation.
_SIMULATION_INPUTS = [
    {
        "subject": "sim", "session": {"mfa": mfa, "risk_score": risk},
        "action": {"name": "sim", "cloud_action": "x:Y", "read_only": ro, "risk": "low"},
        "resource": {"name": "sim", "environment": env, "classification": cls},
        "access_path_exists": path, "justification": just, "approval_present": ap,
    }
    for mfa in (True, False)
    for risk in (0, 99)
    for ro in (True, False)
    for env in ("production", None)
    for cls in ("sensitive", "internal")
    for path in (True, False)
    for just in ({}, {"case_id": "SIM-1"})
    for ap in (True, False)
]


def validate_document(document: dict) -> list[str]:
    errors = []
    if not isinstance(document.get("version"), str) or not document.get("version"):
        errors.append("document.version must be a non-empty string")
    rules = document.get("rules")
    if not isinstance(rules, list) or not rules:
        errors.append("document.rules must be a non-empty list")
        return errors
    seen_ids = set()
    for i, rule in enumerate(rules):
        where = f"rules[{i}]"
        rule_id = rule.get("id")
        if not rule_id:
            errors.append(f"{where}.id missing")
        elif rule_id in seen_ids:
            errors.append(f"{where}.id {rule_id!r} duplicated")
        seen_ids.add(rule_id)
        if rule.get("effect") not in _VALID_EFFECTS:
            errors.append(f"{where}.effect {rule.get('effect')!r} not in {sorted(_VALID_EFFECTS)}")
        when = rule.get("when")
        if not isinstance(when, dict) or not when:
            errors.append(f"{where}.when must be a non-empty object")
        else:
            unknown = set(when) - set(_CONDITIONS)
            if unknown:
                errors.append(f"{where}.when has unknown condition keys: {sorted(unknown)}")
        for j, ob in enumerate(rule.get("obligations", [])):
            if not isinstance(ob, dict) or "type" not in ob:
                errors.append(f"{where}.obligations[{j}] must be an object with a 'type'")
    return errors


def propose_policy(db: Session, document: dict, *, actor: str) -> PolicyRecord:
    """Validate structure, smoke-simulate, store as a draft version."""
    errors = validate_document(document)
    if errors:
        raise PolicyError("; ".join(errors))
    if db.scalar(select(PolicyRecord).where(PolicyRecord.version == document["version"])):
        raise PolicyError(f"version {document['version']!r} already exists")
    for sim_input in _SIMULATION_INPUTS:  # any evaluator crash fails the proposal
        for rule in document["rules"]:
            _rule_matches(rule, sim_input)
    record = PolicyRecord(
        version=document["version"],
        document=document,
        status="draft",
        checksum=checksum(document),
        created_by=actor,
    )
    db.add(record)
    db.flush()
    return record


def activate_policy(db: Session, version: str, *, actor: str) -> PolicyRecord:
    from . import audit  # local import: audit depends on nothing here
    from .models import utcnow

    record = db.scalar(select(PolicyRecord).where(PolicyRecord.version == version))
    if record is None:
        raise PolicyError(f"unknown policy version {version!r}")
    if record.status == "active":
        raise PolicyError(f"version {version!r} is already active")
    if record.checksum != checksum(record.document):
        raise PolicyError(f"version {version!r} failed integrity check; refusing to activate")

    previous = db.scalar(select(PolicyRecord).where(PolicyRecord.status == "active"))
    if previous is not None:
        previous.status = "retired"
    record.status = "active"
    record.activated_at = utcnow()
    audit.append(
        db,
        correlation_id=record.id,
        subject=actor,
        session_id="-",
        event="policy_change",
        action="policy:activate",
        target=version,
        policy_version=version,
        context_summary={
            "previous_version": previous.version if previous else None,
            "checksum": record.checksum,
        },
        result="activated",
    )
    db.flush()
    return record


def rollback_policy(db: Session, *, actor: str) -> PolicyRecord:
    """Re-activate the most recently retired version."""
    candidate = db.scalar(
        select(PolicyRecord)
        .where(PolicyRecord.status == "retired")
        .order_by(PolicyRecord.activated_at.desc())
    )
    if candidate is None:
        raise PolicyError("no retired policy version to roll back to")
    return activate_policy(db, candidate.version, actor=actor)


def _rule_matches(rule: dict, policy_input: dict) -> bool:
    for key, expected in rule["when"].items():
        evaluator = _CONDITIONS.get(key)
        if evaluator is None:  # unknown condition never silently passes
            return False
        if not evaluator(policy_input, expected):
            return False
    return True


def evaluate(db: Session, policy_input: dict) -> Decision:
    record = active_policy(db)
    canonical = json.dumps(policy_input, sort_keys=True, separators=(",", ":"), default=str)
    input_hash = hashlib.sha256(canonical.encode()).hexdigest()

    matched = [r for r in record.document["rules"] if _rule_matches(r, policy_input)]
    summary = [{"id": r["id"], "effect": r["effect"]} for r in matched]

    denies = [r for r in matched if r["effect"] == "deny"]
    if denies:
        return Decision(
            "denied", record.version, summary, reason=denies[0]["description"], input_hash=input_hash
        )

    approvals_needed = [r for r in matched if r["effect"] == "require_approval"]
    if approvals_needed and not policy_input.get("approval_present"):
        return Decision(
            "approval_required",
            record.version,
            summary,
            reason="; ".join(r["description"] for r in approvals_needed),
            input_hash=input_hash,
        )

    allows = [r for r in matched if r["effect"] == "allow"]
    if allows:
        obligations = [o for r in allows for o in r.get("obligations", [])]
        return Decision(
            "allowed",
            record.version,
            summary,
            obligations=obligations,
            reason=allows[0]["description"],
            input_hash=input_hash,
        )

    return Decision("denied", record.version, summary, reason="no matching allow rule", input_hash=input_hash)
