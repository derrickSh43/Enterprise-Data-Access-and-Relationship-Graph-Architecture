import pytest

from eda import audit, feedback


def test_repeated_denials_produce_a_proposed_recommendation(db):
    for _ in range(3):
        audit.append(
            db,
            correlation_id="c1",
            subject="eve",
            session_id="s1",
            event="request",
            action="inspect_instance",
            target="ec2-prod-1",
            result="denied",
        )
    proposals = feedback.run_analyzers(db)
    kinds = {p.kind for p in proposals}
    assert "repeated_denials" in kinds
    assert all(p.status == "proposed" for p in proposals)

    # idempotent: same pattern is not re-proposed
    assert not any(p.kind == "repeated_denials" for p in feedback.run_analyzers(db))


def test_recommendations_require_human_decision_and_are_audited(db):
    for _ in range(3):
        audit.append(
            db,
            correlation_id="c2",
            subject="derrick",
            session_id="s1",
            event="request",
            action="open_ticket",
            target="ec2-prod-1",
            result="approval_required",
        )
    rec = next(p for p in feedback.run_analyzers(db) if p.kind == "approval_bottleneck")

    decided = feedback.decide(db, rec.id, approver="security-lead", approve=True)
    assert decided.status == "approved"
    assert decided.decided_by == "security-lead"

    with pytest.raises(ValueError, match="already approved"):
        feedback.decide(db, rec.id, approver="someone-else", approve=False)

    report = audit.verify_chain(db)
    assert report["ok"] is True
