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


def active_policy(db: Session) -> PolicyRecord:
    record = db.scalar(select(PolicyRecord).where(PolicyRecord.active.is_(True)))
    if record is None:
        record = PolicyRecord(version=DEFAULT_POLICY["version"], document=DEFAULT_POLICY, active=True)
        db.add(record)
        db.flush()
    return record


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
