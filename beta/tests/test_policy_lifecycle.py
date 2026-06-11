"""Policy lifecycle: validated drafts, audited activation, rollback, and
fail-closed integrity on direct database edits."""

import copy

import pytest
from sqlalchemy import select
from sqlalchemy.orm.attributes import flag_modified

from eda import policy
from eda.models import AuditRecord, PolicyRecord


def draft_document(version="2026-test.2"):
    document = copy.deepcopy(policy.DEFAULT_POLICY)
    document["version"] = version
    return document


def test_invalid_documents_rejected(db):
    bad = draft_document()
    bad["rules"][0] = {"id": "x", "effect": "nuke", "when": {"session_mfa": True}}
    with pytest.raises(policy.PolicyError, match="effect"):
        policy.propose_policy(db, bad, actor="security-lead")

    dup = draft_document()
    dup["rules"][1]["id"] = dup["rules"][0]["id"]
    with pytest.raises(policy.PolicyError, match="duplicated"):
        policy.propose_policy(db, dup, actor="security-lead")

    unknown = draft_document()
    unknown["rules"][0]["when"] = {"phase_of_moon": "full"}
    with pytest.raises(policy.PolicyError, match="unknown condition"):
        policy.propose_policy(db, unknown, actor="security-lead")


def test_propose_activate_rollback_cycle_is_audited(db):
    original = policy.active_policy(db).version

    draft = policy.propose_policy(db, draft_document(), actor="security-lead")
    assert draft.status == "draft"
    assert policy.active_policy(db).version == original  # drafts change nothing

    policy.activate_policy(db, draft.version, actor="security-lead")
    db.commit()
    assert policy.active_policy(db).version == draft.version
    assert db.scalar(
        select(PolicyRecord).where(PolicyRecord.version == original)
    ).status == "retired"

    rolled = policy.rollback_policy(db, actor="security-lead")
    db.commit()
    assert rolled.version == original
    assert policy.active_policy(db).version == original

    changes = db.scalars(
        select(AuditRecord).where(AuditRecord.event == "policy_change")
    ).all()
    assert len(changes) == 2
    assert all(c.subject == "security-lead" for c in changes)


def test_duplicate_version_rejected(db):
    policy.propose_policy(db, draft_document("2026-test.9"), actor="lead")
    with pytest.raises(policy.PolicyError, match="already exists"):
        policy.propose_policy(db, draft_document("2026-test.9"), actor="lead")


def test_direct_db_edit_of_active_policy_fails_closed(db):
    record = policy.active_policy(db)
    record.document["rules"].append(
        {"id": "backdoor", "effect": "allow", "when": {"access_path_exists": False}}
    )
    flag_modified(record, "document")
    db.commit()

    with pytest.raises(policy.PolicyError, match="integrity"):
        policy.active_policy(db)
    with pytest.raises(policy.PolicyError, match="integrity"):
        policy.evaluate(db, {})


def test_tampered_draft_cannot_be_activated(db):
    draft = policy.propose_policy(db, draft_document("2026-test.3"), actor="lead")
    draft.document["rules"][0]["effect"] = "allow"
    flag_modified(draft, "document")
    db.commit()
    with pytest.raises(policy.PolicyError, match="integrity"):
        policy.activate_policy(db, "2026-test.3", actor="lead")
