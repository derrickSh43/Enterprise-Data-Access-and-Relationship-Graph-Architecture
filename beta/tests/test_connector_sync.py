from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from eda import access_graph, ingestion
from eda.config import settings
from eda.connectors.contracts import ObjectRecord, Reference, RelationshipRecord, SyncMessage
from eda.connectors.fixture import FixtureConnector
from eda.connectors.sdk import Registry, collect_snapshot
from eda.connectors import sync
from eda.models import ConnectorFact, AccessEdge, ConnectorState


def fixture(db, name="directory", tenant="acme"):
    source, _ = ingestion.register_source(db, source_id=name, tenant_id=tenant,
                                           provider="fixture", allowed_namespace="test:")
    now = datetime.now(timezone.utc) - timedelta(seconds=1)
    refs = [Reference(source_id=name, native_id="test:" + n, kind=k)
            for n, k in [("user", "user"), ("role", "role"), ("account", "account"), ("asset", "asset")]]
    objects = [ObjectRecord(ref=ref, display_name=ref.native_id, observed_at=now) for ref in refs]
    relationships = [
        RelationshipRecord(subject=refs[0], relation="can_assume", target=refs[1], observed_at=now),
        RelationshipRecord(subject=refs[1], relation="role_allows", target=refs[2], observed_at=now,
                           attributes={"actions": ["ec2:DescribeInstances"]}),
        RelationshipRecord(subject=refs[2], relation="account_contains", target=refs[3], observed_at=now),
    ]
    connector = FixtureConnector([(objects, relationships)])
    sync.register(db, source, connector.describe())
    db.commit()
    return source, connector, refs, relationships


def send(db, source, message):
    try:
        result = sync.apply_message(db, source, message)
        db.commit()
        return result
    except Exception:
        db.rollback()
        raise


def path(db, refs, tenant="acme"):
    return access_graph.resolve_path(db, refs[0].canonical_id(tenant), "ec2:DescribeInstances",
                                     refs[-1].canonical_id(tenant), tenant=tenant)


def load(db, source, connector, sequence=1):
    messages = list(collect_snapshot(connector, first_sequence=sequence))
    for msg in messages:
        send(db, source, msg)
    return messages


def test_snapshot_invisible_until_complete_and_membership_revoked(db):
    source, connector, refs, relations = fixture(db)
    messages = list(collect_snapshot(connector))
    send(db, source, messages[0])
    send(db, source, messages[1])
    assert path(db, refs) is None
    send(db, source, messages[2])
    assert path(db, refs) is not None
    send(db, source, SyncMessage(sequence=4, operation="delta", tombstones=[relations[0].key("acme")]))
    assert path(db, refs) is None


def test_interrupted_snapshot_preserves_live_then_empty_complete_revokes(db):
    source, connector, refs, _ = fixture(db)
    load(db, source, connector)
    send(db, source, SyncMessage(sequence=4, operation="begin", snapshot_id="replacement"))
    assert path(db, refs)
    with pytest.raises(ingestion.IngestError, match="partial"):
        send(db, source, SyncMessage(sequence=5, operation="complete", snapshot_id="replacement"))
    assert path(db, refs)
    send(db, source, SyncMessage(sequence=5, operation="complete", snapshot_id="replacement", coverage="complete"))
    assert path(db, refs) is None


def test_abort_preserves_live_and_releases_generation(db):
    source, connector, refs, _ = fixture(db)
    load(db, source, connector)
    send(db, source, SyncMessage(sequence=4, operation="begin", snapshot_id="aborted"))
    send(db, source, SyncMessage(sequence=5, operation="abort", snapshot_id="aborted"))
    assert path(db, refs)
    assert db.get(ConnectorState, source.id).snapshot_id is None


def test_replay_idempotent_conflicting_reuse_and_gap_rejected(db):
    source, connector, refs, _ = fixture(db)
    messages = load(db, source, connector)
    assert send(db, source, messages[-1])["replayed"]
    with pytest.raises(ingestion.IngestError, match="different payload"):
        send(db, source, SyncMessage(sequence=3, operation="delta"))
    with pytest.raises(ingestion.IngestError, match="sequence"):
        send(db, source, SyncMessage(sequence=5, operation="delta"))
    assert path(db, refs)


def test_heartbeat_does_not_refresh_old_authority(db):
    source, connector, refs, _ = fixture(db)
    load(db, source, connector)
    edge = db.scalar(select(AccessEdge).where(AccessEdge.source_id == source.id,
                                            AccessEdge.relation == "role_allows"))
    edge.observed_at = datetime.now(timezone.utc) - timedelta(seconds=settings.source_max_age_seconds + 10)
    source.last_sync_at = datetime.now(timezone.utc)
    db.commit()
    assert path(db, refs) is None


def test_expired_fact_stays_expired_after_reprojection(db):
    source, connector, refs, _ = fixture(db)
    connector.pages[0][1][1].observed_at = datetime.now(timezone.utc) - timedelta(seconds=settings.source_max_age_seconds + 10)
    load(db, source, connector)
    send(db, source, SyncMessage(sequence=4, operation="delta"))
    assert path(db, refs) is None


def test_tenant_source_collisions_are_separate(db):
    source, connector, refs, _ = fixture(db)
    load(db, source, connector)
    other, connector2, refs2, _ = fixture(db, "other-source", "other")
    load(db, other, connector2)
    assert path(db, refs)
    assert path(db, refs2, "other")
    assert path(db, refs2, "acme") is None


def test_partial_visibility_never_emits_complete():
    with pytest.raises(ValueError, match="visibility"):
        list(collect_snapshot(FixtureConnector([], complete=False)))


def test_provider_failure_does_not_emit_complete():
    class Broken(FixtureConnector):
        def snapshot(self):
            yield [], []
            raise RuntimeError("provider unavailable")
    stream = collect_snapshot(Broken([]))
    assert next(stream).operation == "begin"
    assert next(stream).operation == "page"
    with pytest.raises(RuntimeError):
        next(stream)


def test_foreign_overwrite_and_reference_rejected(db):
    source, connector, refs, _ = fixture(db)
    load(db, source, connector)
    foreign = ObjectRecord(ref=Reference(source_id="elsewhere", native_id="test:x", kind="asset"),
                           display_name="x", observed_at=datetime.now(timezone.utc))
    with pytest.raises(ingestion.IngestError, match="foreign"):
        send(db, source, SyncMessage(sequence=4, operation="delta", objects=[foreign]))
    assert path(db, refs)


def test_delta_cannot_interleave_with_snapshot(db):
    source, connector, _, _ = fixture(db)
    send(db, source, SyncMessage(sequence=1, operation="begin", snapshot_id="open"))
    with pytest.raises(ingestion.IngestError, match="interleave"):
        send(db, source, SyncMessage(sequence=2, operation="delta"))


def test_plugin_registration_requires_no_core_change():
    registry = Registry()
    registry.register("fixture", FixtureConnector)
    assert list(collect_snapshot(registry.create("fixture", pages=[])))[-1].coverage == "complete"
    with pytest.raises(ValueError):
        registry.register("fixture", FixtureConnector)


def test_unknown_schema_and_naive_timestamps_rejected():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        SyncMessage(protocol_version="2", sequence=1, operation="delta")
    with pytest.raises(ValidationError):
        ObjectRecord(ref=Reference(source_id="s", native_id="x", kind="file"), display_name="x",
                     observed_at=datetime.now())


def test_versioned_source_cannot_bypass_tombstones_through_legacy_api(db):
    source, connector, refs, _ = fixture(db)
    load(db, source, connector)
    with pytest.raises(ingestion.IngestError, match="sync endpoint"):
        ingestion.ingest(db, source=source, relationships=[])


def test_unsupported_deny_cannot_be_bypassed_by_an_allow_path(db):
    source, connector, refs, _ = fixture(db)
    connector.pages[0][1][0].attributes = {"effect": "deny"}
    load(db, source, connector)
    assert path(db, refs) is None


def test_source_cannot_take_over_existing_legacy_node(db):
    source, _ = ingestion.register_source(db, source_id="legacy-a", tenant_id="t", provider="x", allowed_namespace="x:")
    other, _ = ingestion.register_source(db, source_id="legacy-b", tenant_id="t", provider="x", allowed_namespace="x:")
    relationship = {"subject": {"kind": "user", "id": "x:u"}, "relation": "member_of",
                    "target": {"kind": "group", "id": "x:g"}}
    ingestion.ingest(db, source=source, relationships=[relationship])
    db.commit()
    with pytest.raises(ingestion.IngestError, match="another source"):
        ingestion.ingest(db, source=other, relationships=[relationship])
