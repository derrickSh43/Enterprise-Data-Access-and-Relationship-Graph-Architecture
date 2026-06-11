"""Local AI Feedback Loop: observes, proposes - never enforces.

Analyzers run locally over the audit log and produce Recommendations that sit
in `proposed` until a human approves or rejects them. Approving a
recommendation here records the decision; applying it (a policy edit, a graph
change) is a separate, versioned, audited act.

The analyzers are deterministic pattern detectors so the reference
implementation has zero model dependencies. `NarrativeGateway` is the seam for
a customer-hosted local model (summaries, explanations); the default
implementation is template-based and fully offline.
"""

from collections import Counter
from fnmatch import fnmatch
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit
from .models import AuditRecord, Recommendation, utcnow


def _norm(identifier: str) -> str:
    """Canonical form for authority identifiers so naming differences
    (case, whitespace) never create false least-privilege findings."""
    return identifier.strip().lower()


class NarrativeGateway(Protocol):
    def summarize(self, facts: dict) -> str: ...


class TemplateNarrative:
    """Offline default. Swap for a local-LLM gateway without touching analyzers."""

    def summarize(self, facts: dict) -> str:
        return facts["template"].format(**facts)


def _existing(db: Session, kind: str, fingerprint: str) -> bool:
    rows = db.scalars(select(Recommendation).where(Recommendation.kind == kind)).all()
    return any(r.details.get("fingerprint") == fingerprint for r in rows)


def run_analyzers(db: Session, narrative: NarrativeGateway | None = None) -> list[Recommendation]:
    narrative = narrative or TemplateNarrative()
    records = db.scalars(select(AuditRecord).order_by(AuditRecord.seq)).all()
    proposals: list[Recommendation] = []

    # 1. Repeated denials: same subject+action denied 3+ times -> review policy or training.
    denial_counts = Counter(
        (r.subject, r.action, r.tenant_id) for r in records if r.result == "denied" and r.action
    )
    for (subject, action, tenant_id), count in denial_counts.items():
        if count < 3:
            continue
        fingerprint = f"denials:{subject}:{action}"
        if _existing(db, "repeated_denials", fingerprint):
            continue
        proposals.append(
            Recommendation(
                kind="repeated_denials",
                tenant_id=tenant_id,
                summary=narrative.summarize(
                    {
                        "template": (
                            "{subject} was denied '{action}' {count} times. Review whether the "
                            "policy is correct (then leave it) or the subject needs a documented "
                            "access path / workflow guidance."
                        ),
                        "subject": subject,
                        "action": action,
                        "count": count,
                    }
                ),
                details={"fingerprint": fingerprint, "subject": subject, "action": action, "count": count},
            )
        )

    # 2. Approval bottleneck: an action repeatedly requiring approval -> propose a
    #    pre-approved workflow template (humans decide; this only suggests).
    approval_counts = Counter(
        (r.action, r.tenant_id) for r in records if r.result == "approval_required" and r.action
    )
    for (action, tenant_id), count in approval_counts.items():
        if count < 3:
            continue
        fingerprint = f"approval_bottleneck:{action}"
        if _existing(db, "approval_bottleneck", fingerprint):
            continue
        proposals.append(
            Recommendation(
                kind="approval_bottleneck",
                tenant_id=tenant_id,
                summary=narrative.summarize(
                    {
                        "template": (
                            "Action '{action}' hit the approval gate {count} times. Consider an "
                            "approval workflow template or a scoped standing policy for the "
                            "lowest-risk variant."
                        ),
                        "action": action,
                        "count": count,
                    }
                ),
                details={"fingerprint": fingerprint, "action": action, "count": count},
            )
        )

    # 3. Access drift / least privilege: authority proven on access paths but
    #    never exercised -> candidates for narrowing. Both sides are
    #    normalized, granted wildcards are matched against observed calls, and
    #    approval capabilities count approval decisions as exercise - so
    #    naming differences never produce false findings.
    proven = {
        _norm(a)
        for r in records
        if r.access_path
        for hop in r.access_path
        for a in hop.get("actions", [])
    }
    exercised = {
        _norm(c.get("service", "") + ":" + c.get("call", ""))
        for r in records
        if r.result == "allowed" and r.api_calls
        for c in r.api_calls
    }
    exercised |= {
        _norm(f"approval:{r.action}")
        for r in records
        if r.event == "approval_decision" and r.action
    }
    unused = sorted(
        pattern
        for pattern in proven
        if not pattern.startswith("admin:")  # exercised out-of-band by admin surfaces
        and not any(fnmatch(call, pattern) for call in exercised)
    )
    if unused:
        fingerprint = "unused:" + ",".join(unused)
        if not _existing(db, "least_privilege", fingerprint):
            proposals.append(
                Recommendation(
                    kind="least_privilege",
                    summary=narrative.summarize(
                        {
                            "template": (
                                "Authority for {n} action(s) exists on proven paths but was never "
                                "exercised: {unused}. Candidates for removal or tighter scoping."
                            ),
                            "n": len(unused),
                            "unused": ", ".join(unused),
                        }
                    ),
                    details={"fingerprint": fingerprint, "unused_actions": unused},
                )
            )

    for p in proposals:
        db.add(p)
    db.flush()
    return proposals


def decide(db: Session, recommendation_id: str, *, approver: str, approve: bool) -> Recommendation:
    rec = db.get(Recommendation, recommendation_id)
    if rec is None:
        raise ValueError("unknown recommendation")
    if rec.status != "proposed":
        raise ValueError(f"recommendation already {rec.status}")
    rec.status = "approved" if approve else "rejected"
    rec.decided_by = approver
    audit.append(
        db,
        correlation_id=rec.id,
        subject=approver,
        session_id="-",
        event="recommendation_decision",
        action="feedback:decide",
        target=rec.kind,
        result=rec.status,
        context_summary={"recommendation_id": rec.id, "summary": rec.summary},
    )
    db.flush()
    return rec
