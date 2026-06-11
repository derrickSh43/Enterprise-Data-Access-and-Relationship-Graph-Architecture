"""Audit / Evidence Layer: append-only, hash-chained.

Each record's hash covers its canonical content plus the previous record's
hash, so any retroactive edit breaks the chain from that point forward.
`verify_chain` walks the whole log and reports the first broken link.
(Production hardening: ship the head hash to an external anchor - object-lock
storage, transparency log, or a second trust domain.)
"""

import hashlib
import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .models import AuditRecord

GENESIS = "0" * 64

# Appends are serialized in-process; the unique constraint on prev_hash is the
# database-level backstop so two processes can never fork the chain - the
# loser gets an IntegrityError instead of a competing head.
_append_lock = threading.Lock()

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
    """Append one fully-formed record: predecessor lookup, hashing, and
    insert happen atomically under the chain lock."""
    with _append_lock:
        prev = db.scalar(select(AuditRecord).order_by(AuditRecord.seq.desc()))
        record = AuditRecord(
            id=uuid.uuid4().hex,
            ts=datetime.now(timezone.utc),
            prev_hash=prev.hash if prev else GENESIS,
            hash="",
            **fields,
        )
        record.hash = _record_hash(record, record.prev_hash)
        db.add(record)
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


# ---------------------------------------------------------------------------
# External anchoring: the local chain detects modification, but a database
# administrator could recompute it wholesale. Signed chain heads written to a
# separate trust domain (append-only file here; object-lock storage or a
# transparency log in production) make that recomputation detectable.
# ---------------------------------------------------------------------------
_ephemeral_key = None


def _anchor_key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    global _ephemeral_key
    if settings.audit_anchor_key:
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(settings.audit_anchor_key))
    if _ephemeral_key is None:
        _ephemeral_key = Ed25519PrivateKey.generate()
    return _ephemeral_key


def anchor_chain(db: Session) -> dict:
    """Sign the current chain head and append it to the anchor log."""
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat,
    )

    head = db.scalar(select(AuditRecord).order_by(AuditRecord.seq.desc()))
    if head is None:
        raise ValueError("no audit records to anchor")
    key = _anchor_key()
    payload = {
        "seq": head.seq,
        "hash": head.hash,
        "anchored_at": datetime.now(timezone.utc).isoformat(),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    anchor = {
        **payload,
        "signature": key.sign(canonical.encode()).hex(),
        "public_key": key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
    }
    path = Path(settings.audit_anchor_path)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(anchor, sort_keys=True) + "\n")
    return anchor


def verify_anchors(db: Session) -> dict:
    """Check every anchor: valid signature, and the anchored (seq, hash) still
    present in the chain. A recomputed chain no longer matches its anchors."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    path = Path(settings.audit_anchor_path)
    if not path.exists():
        return {"ok": True, "anchors": 0, "failures": []}

    by_seq = {
        r.seq: r.hash for r in db.scalars(select(AuditRecord)).all()
    }
    failures = []
    anchors = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    for i, anchor in enumerate(anchors):
        payload = {"seq": anchor["seq"], "hash": anchor["hash"],
                   "anchored_at": anchor["anchored_at"]}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(anchor["public_key"])).verify(
                bytes.fromhex(anchor["signature"]), canonical.encode()
            )
        except (InvalidSignature, ValueError):
            failures.append({"anchor": i, "reason": "invalid signature"})
            continue
        if by_seq.get(anchor["seq"]) != anchor["hash"]:
            failures.append({"anchor": i, "reason": "chain no longer matches anchored head"})
    return {"ok": not failures, "anchors": len(anchors), "failures": failures}
