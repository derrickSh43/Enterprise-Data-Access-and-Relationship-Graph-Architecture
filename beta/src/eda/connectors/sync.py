"""Transactional source-owned inventory and authority projection.

Sequence compare-and-swap serializes a source. All calls are transactions: callers
commit on success and roll back on any exception. Staged snapshots are invisible.
"""
from datetime import datetime, timezone
import json
import uuid

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from .. import audit
from ..models import (AccessNode, AccessEdge, ObjectNode, ObjectEdge, RelationshipSource,
                      ConnectorState, ConnectorFact, ConnectorReceipt)
from ..ingestion import IngestError, ALLOWED_KINDS
from ..access_graph import TRAVERSABLE
from .contracts import Manifest, ObjectRecord, RelationshipRecord, SyncMessage, digest


def register(db: Session, source: RelationshipSource, manifest: Manifest):
    """Administrative operation: manifest includes trusted assertion rules."""
    if db.get(ConnectorState, source.id):
        raise IngestError(409, "connector already configured")
    for foreign in manifest.foreign_references:
        target = db.get(RelationshipSource, foreign)
        if target is None or target.tenant_id != source.tenant_id:
            raise IngestError(422, "foreign source must exist within tenant")
    db.add(ConnectorState(source_id=source.id, manifest=manifest.model_dump(mode="json")))
    audit.append(db, correlation_id=uuid.uuid4().hex, subject="administrator", session_id="-",
                 event="connector_registration", action="register_manifest", target=source.id,
                 result="accepted", tenant_id=source.tenant_id,
                 context_summary={"manifest_digest": digest(manifest.model_dump(mode="json"))})
    db.flush()


def _validate_fact(db, source, manifest, record):
    now = datetime.now(timezone.utc)
    if record.observed_at > now:
        raise IngestError(422, "future evidence timestamp")
    refs = [record.ref] if isinstance(record, ObjectRecord) else [record.subject, record.target]
    if isinstance(record, ObjectRecord) and record.ref.source_id != source.id:
        raise IngestError(403, "cannot overwrite foreign object")
    if isinstance(record, RelationshipRecord) and record.relation not in manifest.relations:
        raise IngestError(403, "relationship assertion not permitted")
    if isinstance(record, RelationshipRecord) and record.relation == "role_allows":
        actions = record.attributes.get("actions", [])
        if not isinstance(actions, list) or any(not isinstance(a, str) or not a for a in actions):
            raise IngestError(422, "actions must be non-empty strings in a list")
    for ref in refs:
        if ref.source_id == source.id:
            if ref.kind not in manifest.object_kinds or not ref.native_id.startswith(source.allowed_namespace):
                raise IngestError(403, "object outside source manifest/namespace")
        else:
            other = db.get(RelationshipSource, ref.source_id)
            if (other is None or other.tenant_id != source.tenant_id or not other.enabled
                    or record.relation not in manifest.foreign_references.get(ref.source_id, [])):
                raise IngestError(403, "foreign reference not permitted")


def _upsert_fact(db, source, generation, record, kind):
    key = record.key(source.tenant_id)
    fact = db.scalar(select(ConnectorFact).where(ConnectorFact.source_id == source.id,
                    ConnectorFact.fact_key == key, ConnectorFact.generation == generation))
    payload = record.model_dump(mode="json")
    if fact:
        if datetime.fromisoformat(fact.payload["observed_at"].replace("Z", "+00:00")) > record.observed_at:
            raise IngestError(409, "older evidence cannot replace newer evidence")
        fact.payload = payload
    else:
        db.add(ConnectorFact(source_id=source.id, fact_key=key, generation=generation, kind=kind, payload=payload))
    db.flush()


def _project(db, source, manifest):
    """Only explicit platform-relation connectors project authority.

    Inventory-only native collectors never turn policy strings into grants.
    All projected IDs are deterministic and tenant/source-qualified.
    """
    facts = db.scalars(select(ConnectorFact).where(ConnectorFact.source_id == source.id,
                                                  ConnectorFact.generation == "live")).all()
    db.execute(delete(AccessEdge).where(AccessEdge.source_id == source.id))
    # Node deletion intentionally does not cascade to another source's facts.
    # A missing authoritative node makes foreign paths unavailable.
    db.execute(delete(AccessNode).where(AccessNode.source_id == source.id))
    old_objects = db.scalars(select(ObjectNode).where(ObjectNode.tenant_id == source.tenant_id)).all()
    for old in old_objects:
        if old.attrs.get("_source_id") == source.id:
            db.delete(old)
    for old in db.scalars(select(ObjectEdge)).all():
        if old.attrs.get("_source_id") == source.id:
            db.delete(old)
    db.flush()
    object_records = [ObjectRecord.model_validate(f.payload) for f in facts if f.kind == "object"]
    for obj in object_records:
        canonical = obj.key(source.tenant_id)
        db.add(ObjectNode(id=canonical[4:36], kind=obj.ref.kind, name=canonical, tenant_id=source.tenant_id,
                          attrs={**obj.attributes, "_source_id": source.id, "native_id": obj.ref.native_id,
                                 "display_name": obj.display_name, "observed_at": obj.observed_at.isoformat()}))
        if obj.ref.kind in ALLOWED_KINDS:
            db.add(AccessNode(id=canonical[4:36], kind=obj.ref.kind, name=canonical,
                             tenant_id=source.tenant_id, external_id=obj.ref.native_id,
                             source_id=source.id, observed_at=obj.observed_at, attrs=obj.attributes))
    db.flush()
    for fact in facts:
        if fact.kind != "relationship":
            continue
        relation = RelationshipRecord.model_validate(fact.payload)
        if relation.relation in TRAVERSABLE:
            continue
        src = db.get(ObjectNode, relation.subject.canonical_id(source.tenant_id)[4:36])
        dst = db.get(ObjectNode, relation.target.canonical_id(source.tenant_id)[4:36])
        if src is not None and dst is not None:
            db.add(ObjectEdge(src_id=src.id, dst_id=dst.id, relation=relation.relation,
                              attrs={**relation.attributes, "_source_id": source.id}))
    db.flush()
    if manifest.permission_semantics != "platform_relations":
        return
    # Conservative source-wide refusal prevents an unsupported deny/condition
    # from being silently skipped while another path supplies an allow.
    if any(f.payload.get("attributes", {}).get("conditions")
           or f.payload.get("attributes", {}).get("unsupported")
           or f.payload.get("attributes", {}).get("effect", "allow") != "allow"
           for f in facts if f.kind == "relationship"):
        return
    for fact in facts:
        if fact.kind != "relationship":
            continue
        rel = RelationshipRecord.model_validate(fact.payload)
        if rel.relation not in TRAVERSABLE:
            continue
        src = db.get(AccessNode, rel.subject.canonical_id(source.tenant_id)[4:36])
        dst = db.get(AccessNode, rel.target.canonical_id(source.tenant_id)[4:36])
        if src is None or dst is None:
            continue  # unresolved reference never creates authority
        db.add(AccessEdge(src_id=src.id, dst_id=dst.id, relation=rel.relation,
                          tenant_id=source.tenant_id, source_id=source.id,
                          observed_at=rel.observed_at, attrs=rel.attributes))
    db.flush()


def apply_message(db: Session, source: RelationshipSource, message: SyncMessage) -> dict:
    if not source.enabled:
        raise IngestError(403, "source disabled")
    payload = message.model_dump(mode="json")
    if len(json.dumps(payload).encode()) > 2 * 1024 * 1024:
        raise IngestError(413, "sync message exceeds 2 MiB")
    hashed = digest(payload)
    receipt = db.scalar(select(ConnectorReceipt).where(ConnectorReceipt.source_id == source.id,
                                                      ConnectorReceipt.sequence == message.sequence))
    if receipt:
        if receipt.digest != hashed:
            raise IngestError(409, "sequence reused with different payload")
        return {**receipt.result, "replayed": True}
    state = db.get(ConnectorState, source.id)
    if state is None:
        raise IngestError(409, "connector manifest not registered")
    if message.sequence != state.sequence + 1:
        raise IngestError(409, "sequence gap or stale event")
    locked = db.execute(update(ConnectorState).where(ConnectorState.source_id == source.id,
                        ConnectorState.sequence == state.sequence).values(sequence=message.sequence))
    if locked.rowcount != 1:
        raise IngestError(409, "concurrent sync; retry from acknowledged sequence")
    manifest = Manifest.model_validate(state.manifest)
    if message.operation == "delta" and "changes" not in manifest.capabilities:
        raise IngestError(403, "changes capability unavailable")
    if message.operation != "delta" and "snapshot" not in manifest.capabilities:
        raise IngestError(403, "snapshot capability unavailable")
    for fact in [*message.objects, *message.relationships]:
        _validate_fact(db, source, manifest, fact)
    if message.snapshot_id == "live":
        raise IngestError(422, "reserved snapshot identifier")
    if message.operation == "begin":
        if state.snapshot_id:
            raise IngestError(409, "abort or complete active snapshot first")
        # A fresh snapshot identifier must not alias staged data from an old run.
        if db.scalar(select(ConnectorFact.id).where(ConnectorFact.source_id == source.id,
                                                   ConnectorFact.generation == message.snapshot_id)):
            raise IngestError(409, "snapshot generation already exists")
        state.snapshot_id = message.snapshot_id
    elif message.operation in {"page", "complete", "abort"}:
        if state.snapshot_id != message.snapshot_id:
            raise IngestError(409, "snapshot mismatch")
        if message.operation == "page":
            for obj in message.objects:
                _upsert_fact(db, source, message.snapshot_id, obj, "object")
            for rel in message.relationships:
                _upsert_fact(db, source, message.snapshot_id, rel, "relationship")
        elif message.operation == "abort":
            db.execute(delete(ConnectorFact).where(ConnectorFact.source_id == source.id,
                       ConnectorFact.generation == message.snapshot_id))
            state.snapshot_id = None
        else:
            if message.coverage != "complete":
                raise IngestError(409, "partial snapshot cannot replace live facts")
            db.execute(delete(ConnectorFact).where(ConnectorFact.source_id == source.id,
                                                   ConnectorFact.generation == "live"))
            db.execute(update(ConnectorFact).where(ConnectorFact.source_id == source.id,
                       ConnectorFact.generation == message.snapshot_id).values(generation="live"))
            state.snapshot_id = None
            state.coverage = "complete"
            _project(db, source, manifest)
            source.last_sync_at = datetime.now(timezone.utc)
    else:
        if state.snapshot_id:
            raise IngestError(409, "delta cannot interleave with snapshot")
        for key in message.tombstones:
            db.execute(delete(ConnectorFact).where(ConnectorFact.source_id == source.id,
                       ConnectorFact.generation == "live", ConnectorFact.fact_key == key))
        for obj in message.objects:
            _upsert_fact(db, source, "live", obj, "object")
        for rel in message.relationships:
            _upsert_fact(db, source, "live", rel, "relationship")
        _project(db, source, manifest)
        source.last_sync_at = datetime.now(timezone.utc)
    result = {"source_id": source.id, "sequence": message.sequence,
              "operation": message.operation, "coverage": state.coverage}
    audit.append(db, correlation_id=uuid.uuid4().hex, subject=f"collector:{source.id}", session_id="-",
                 event="connector_sync", action=message.operation, target=source.id, result="accepted",
                 tenant_id=source.tenant_id, context_summary={**result, "payload_digest": hashed})
    db.add(ConnectorReceipt(source_id=source.id, sequence=message.sequence, digest=hashed, result=result))
    db.flush()
    return result
