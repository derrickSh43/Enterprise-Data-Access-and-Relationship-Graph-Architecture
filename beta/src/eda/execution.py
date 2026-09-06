"""Durable operation identifiers and explicit uncertain outcomes.

This version executes synchronously after durable intent. A crash never triggers
an automatic retry: running/authorized records require explicit reconciliation.
Distributed queue dispatch and worker fencing are separate release requirements.
"""
import hashlib
from datetime import datetime, timezone
from sqlalchemy import select
from .models import Execution


def operation_id(tenant, subject, key):
    import json
    return hashlib.sha256(json.dumps([tenant, subject, key]).encode()).hexdigest()[:32]


def replay(record):
    return {"correlation_id": record.correlation_id,
            "outcome": "allowed" if record.state == "succeeded" else record.state,
            "stages": {"execution": {"id": record.id, "state": record.state, "replayed": True}},
            "note": "Existing operation returned; no new execution or context disclosure"}


def mark_interrupted(db, *, before):
    """Recovery operation, run only after the corresponding workers are stopped.

    Does not claim failure or repeat the provider call. Administrator must reconcile
    with native activity evidence before deciding whether a new operation is safe.
    """
    from . import audit
    records = db.scalars(select(Execution).where(Execution.state.in_(["authorized", "running"]),
                                                Execution.updated_at < before)).all()
    for record in records:
        record.state = "outcome_unknown"
        record.updated_at = datetime.now(timezone.utc)
        audit.append(db, correlation_id=record.correlation_id, subject="recovery", session_id="-",
                     event="execution_recovery", action="mark_interrupted", target=record.id,
                     result="outcome_unknown", tenant_id=record.tenant_id)
    db.flush()
    return len(records)
