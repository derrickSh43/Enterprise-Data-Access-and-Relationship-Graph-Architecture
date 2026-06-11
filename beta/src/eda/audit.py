"""Audit / Evidence Layer: append-only, hash-chained.

Each record's hash covers its canonical content plus the previous record's
hash, so any retroactive edit breaks the chain from that point forward.
`verify_chain` walks the whole log and reports the first broken link.
(Production hardening: ship the head hash to an external anchor - object-lock
storage, transparency log, or a second trust domain.)
"""

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AuditRecord

GENESIS = "0" * 64

_CHAINED_FIELDS = (
    "id",
    "correlation_id",
    "subject",
    "session_id",
    "event",
    "action",
    "target",
    "access_path",
    "policy_input",
    "policy_decision",
    "policy_version",
    "approval",
    "grant",
    "api_calls",
    "context_summary",
    "result",
    "error",
)


def _ts_iso(ts: datetime | None) -> str | None:
    """Canonical UTC timestamp. SQLite round-trips datetimes as naive, so the
    hash must not depend on tzinfo presence."""
    if ts is None:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).isoformat()


def _record_hash(record: AuditRecord, prev_hash: str) -> str:
    payload = {f: getattr(record, f) for f in _CHAINED_FIELDS}
    payload["ts"] = _ts_iso(record.ts)
    payload["prev_hash"] = prev_hash
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def append(db: Session, **fields) -> AuditRecord:
    record = AuditRecord(**fields, prev_hash=GENESIS, hash="")
    db.add(record)
    db.flush()  # assigns seq and default ts

    prev = db.scalar(
        select(AuditRecord).where(AuditRecord.seq < record.seq).order_by(AuditRecord.seq.desc())
    )
    record.prev_hash = prev.hash if prev else GENESIS
    record.hash = _record_hash(record, record.prev_hash)
    db.flush()
    return record


def verify_chain(db: Session) -> dict:
    records = db.scalars(select(AuditRecord).order_by(AuditRecord.seq)).all()
    prev_hash = GENESIS
    for r in records:
        if r.prev_hash != prev_hash or r.hash != _record_hash(r, prev_hash):
            return {"ok": False, "records": len(records), "first_broken_seq": r.seq}
        prev_hash = r.hash
    return {"ok": True, "records": len(records), "first_broken_seq": None}
