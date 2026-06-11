"""Audit-chain concurrency control and external anchoring."""

import json

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from eda import audit
from eda.config import settings
from eda.models import AuditRecord


def append(db, **over):
    fields = dict(
        correlation_id="c1", subject="derrick", session_id="s1", event="request",
        action="inspect_instance", target="ec2-prod-1", result="allowed",
    )
    fields.update(over)
    return audit.append(db, **fields)


def test_competing_chain_heads_blocked_at_database_level(db):
    """The unique constraint on prev_hash is the cross-process backstop: a
    second record claiming the same predecessor cannot be inserted."""
    first = append(db)
    db.commit()

    forged = AuditRecord(
        id="f" * 32, correlation_id="x", subject="attacker", session_id="-",
        event="request", result="allowed", prev_hash=first.prev_hash, hash="f" * 64,
    )
    db.add(forged)
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()


def test_appends_chain_strictly(db):
    records = [append(db, correlation_id=f"c{i}") for i in range(5)]
    db.commit()
    hashes = [r.hash for r in records]
    assert len(set(hashes)) == 5
    for prev, record in zip(records, records[1:]):
        assert record.prev_hash == prev.hash
    assert audit.verify_chain(db)["ok"] is True


@pytest.fixture()
def anchor_file(tmp_path):
    original = settings.audit_anchor_path
    object.__setattr__(settings, "audit_anchor_path", str(tmp_path / "anchors.jsonl"))
    try:
        yield tmp_path / "anchors.jsonl"
    finally:
        object.__setattr__(settings, "audit_anchor_path", original)


def test_anchor_and_verify(db, anchor_file):
    append(db)
    db.commit()
    anchor = audit.anchor_chain(db)
    assert anchor["seq"] == 1
    assert anchor_file.exists()
    report = audit.verify_anchors(db)
    assert report == {"ok": True, "anchors": 1, "failures": []}


def test_recomputed_chain_no_longer_matches_anchor(db, anchor_file):
    """A DBA can recompute the whole local chain, but the anchored head in the
    external trust domain then disagrees."""
    record = append(db)
    db.commit()
    audit.anchor_chain(db)

    # simulate full recompute: change content AND rewrite hashes consistently
    record.result = "denied"
    record.hash = audit._record_hash(record, record.prev_hash)
    db.commit()
    assert audit.verify_chain(db)["ok"] is True  # local chain looks clean...

    report = audit.verify_anchors(db)
    assert report["ok"] is False  # ...but the anchor exposes the rewrite
    assert report["failures"][0]["reason"] == "chain no longer matches anchored head"


def test_forged_anchor_signature_detected(db, anchor_file):
    append(db)
    db.commit()
    audit.anchor_chain(db)
    forged = json.loads(anchor_file.read_text().strip())
    forged["signature"] = "00" * 64
    anchor_file.write_text(json.dumps(forged) + "\n")
    report = audit.verify_anchors(db)
    assert report["ok"] is False
    assert report["failures"][0]["reason"] == "invalid signature"
