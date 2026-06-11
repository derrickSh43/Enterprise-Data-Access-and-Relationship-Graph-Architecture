"""Collector ingestion: source-bound credentials, namespace confinement,
schema validation, provenance, and resolver compatibility."""

import pytest

from eda import access_graph, ingestion

SECRET = "collector-s3cret"


def make_source(db, **overrides):
    fields = dict(
        source_id="okta-directory-prod",
        tenant_id="acme",
        provider="okta",
        allowed_namespace="okta:",
        secret=SECRET,
    )
    fields.update(overrides)
    source, _ = ingestion.register_source(db, **fields)
    return source


def rel(subject_id, relation, target_id, skind="user", tkind="group", attrs=None):
    return {
        "subject": {"kind": skind, "id": subject_id},
        "relation": relation,
        "target": {"kind": tkind, "id": target_id},
        "attributes": attrs or {},
    }


FULL_PATH = [
    rel("okta:00u123", "member_of", "okta:g-sec"),
    rel("okta:g-sec", "assigned", "okta:ps-ro", skind="group", tkind="permission_set"),
    rel("okta:ps-ro", "can_assume", "okta:r-audit", skind="permission_set", tkind="role"),
    rel("okta:r-audit", "role_allows", "okta:acct-prod", skind="role", tkind="account",
        attrs={"actions": ["ec2:Describe*"]}),
    rel("okta:acct-prod", "account_contains", "okta:i-0abc", skind="account", tkind="asset"),
]


def test_imported_relationships_resolve_through_existing_resolver(db):
    source = make_source(db)
    summary = ingestion.ingest(db, source=source, relationships=FULL_PATH)
    db.commit()
    assert summary["nodes_created"] == 6
    assert summary["edges_created"] == 5

    path = access_graph.resolve_path(db, "okta:00u123", "ec2:DescribeInstances", "okta:i-0abc")
    assert path is not None
    assert [h["relation"] for h in path.hops] == [
        "member_of", "assigned", "can_assume", "role_allows", "account_contains"
    ]


def test_provenance_recorded_on_nodes_and_edges(db):
    source = make_source(db)
    ingestion.ingest(db, source=source, relationships=[FULL_PATH[0]])
    node = access_graph.get_node(db, "user", "okta:00u123")
    assert node.source_id == "okta-directory-prod"
    assert node.tenant_id == "acme"
    assert node.external_id == "okta:00u123"
    assert node.observed_at is not None
    assert source.last_sync_at is not None


def test_cross_namespace_write_rejected_atomically(db):
    source = make_source(db)
    batch = [FULL_PATH[0], rel("entra:alien", "member_of", "okta:g-sec")]
    with pytest.raises(ingestion.IngestError) as excinfo:
        ingestion.ingest(db, source=source, relationships=batch)
    assert excinfo.value.status == 422
    assert any("outside source namespace" in e for e in excinfo.value.detail)
    # all-or-nothing: the valid row was not applied either
    assert access_graph.get_node(db, "user", "okta:00u123") is None


def test_disallowed_relation_and_kind_rejected(db):
    source = make_source(db)
    with pytest.raises(ingestion.IngestError, match="relation"):
        ingestion.ingest(db, source=source,
                         relationships=[rel("okta:a", "owns_company", "okta:b")])
    with pytest.raises(ingestion.IngestError, match="kind"):
        ingestion.ingest(db, source=source,
                         relationships=[rel("okta:a", "member_of", "okta:b", skind="alien")])


def test_kind_conflict_rejected(db):
    source = make_source(db)
    ingestion.ingest(db, source=source, relationships=[FULL_PATH[0]])
    with pytest.raises(ingestion.IngestError, match="already exists as kind"):
        ingestion.ingest(
            db, source=source,
            relationships=[rel("okta:00u123", "member_of", "okta:g2", skind="group")],
        )


def test_batch_size_limit(db):
    source = make_source(db)
    batch = [rel(f"okta:u{i}", "member_of", "okta:g-sec") for i in range(5)]
    with pytest.raises(ingestion.IngestError, match="exceeds limit"):
        ingestion.ingest(db, source=source, relationships=batch, max_batch=3)


def test_collector_auth_fails_closed(db):
    make_source(db)
    db.commit()
    # wrong secret
    with pytest.raises(ingestion.IngestError) as e1:
        ingestion.authenticate_collector(db, "okta-directory-prod", "wrong")
    assert e1.value.status == 403
    # unknown source: indistinguishable 403
    with pytest.raises(ingestion.IngestError) as e2:
        ingestion.authenticate_collector(db, "no-such-source", SECRET)
    assert e2.value.status == 403


def test_disabled_source_fails_closed(db):
    source = make_source(db)
    source.enabled = False
    db.commit()
    with pytest.raises(ingestion.IngestError) as excinfo:
        ingestion.authenticate_collector(db, "okta-directory-prod", SECRET)
    assert excinfo.value.status == 403


def test_ingestion_endpoint_over_http(client):
    from eda.db import SessionLocal

    with SessionLocal() as db:
        make_source(db)
        db.commit()

    headers = {"Authorization": f"Bearer {SECRET}"}
    ok = client.post(
        "/relationship-sources/okta-directory-prod/relationships",
        json={"relationships": FULL_PATH}, headers=headers,
    )
    assert ok.status_code == 200
    assert ok.json()["edges_created"] == 5

    forged = client.post(
        "/relationship-sources/okta-directory-prod/relationships",
        json={"relationships": FULL_PATH},
        headers={"Authorization": "Bearer not-the-secret"},
    )
    assert forged.status_code == 403

    cross = client.post(
        "/relationship-sources/okta-directory-prod/relationships",
        json={"relationships": [rel("entra:alien", "member_of", "okta:g-sec")]},
        headers=headers,
    )
    assert cross.status_code == 422


def test_idempotency_key_prevents_duplicate_application(client):
    from eda.db import SessionLocal

    with SessionLocal() as db:
        make_source(db)
        db.commit()

    headers = {"Authorization": f"Bearer {SECRET}", "Idempotency-Key": "batch-001"}
    first = client.post(
        "/relationship-sources/okta-directory-prod/relationships",
        json={"relationships": FULL_PATH}, headers=headers,
    ).json()
    assert first["edges_created"] == 5

    replay = client.post(
        "/relationship-sources/okta-directory-prod/relationships",
        json={"relationships": FULL_PATH}, headers=headers,
    ).json()
    assert replay["idempotent_replay"] is True
    assert replay["edges_created"] == 5  # original summary, nothing reapplied


def test_okta_adapter_emits_ingestible_batch(db):
    from eda.adapters import okta

    groups = [{"id": "g-sec", "profile": {"name": "security-engineers"}}]
    memberships = {"g-sec": [{"id": "00u123", "profile": {"login": "derrick@acme.com"}}]}
    relationships = okta.directory_to_relationships(groups, memberships)
    assert relationships[0]["subject"]["id"] == "okta:00u123"

    source = make_source(db)
    summary = ingestion.ingest(db, source=source, relationships=relationships)
    assert summary["edges_created"] == 1
    edge_attrs = access_graph.get_node(db, "user", "okta:00u123")
    assert edge_attrs is not None
