"""Administrative endpoint authorization (capability, not just authn) and
tenant isolation of audit/recommendation queries."""

from eda import ingestion


def make_session(client, subject, **kw):
    return client.post("/identity/sessions", json={"subject": subject, **kw}).json()[
        "session_token"
    ]


def auth(token):
    return {"Authorization": f"Bearer {token}"}


ADMIN_GETS = ["/audit/records", "/audit/verify", "/audit/anchors/verify",
              "/policy/active", "/feedback/recommendations", "/metrics",
              "/access-graph/path?subject=derrick&action=x&resource=y"]


def test_authentication_alone_is_insufficient_for_admin_surfaces(client):
    derrick = make_session(client, "derrick")  # authenticated, mapped, no admin capability
    for path in ADMIN_GETS:
        response = client.get(path, headers=auth(derrick))
        assert response.status_code == 403, path
        assert "requires capability" in response.json()["detail"], path
    assert client.post("/feedback/run", headers=auth(derrick)).status_code == 403
    assert client.post("/audit/anchors", headers=auth(derrick)).status_code == 403
    assert client.post(
        "/policy/versions", json={"document": {}}, headers=auth(derrick)
    ).status_code == 403


def test_admin_capability_path_grants_access(client):
    lead = make_session(client, "security-lead")
    for path in ADMIN_GETS:
        assert client.get(path, headers=auth(lead)).status_code == 200, path


def test_unauthenticated_admin_calls_rejected(client):
    assert client.get("/audit/records").status_code == 401


def test_health_endpoints_are_open(client):
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/readyz").json() == {"status": "ready"}


def test_audit_queries_are_tenant_scoped(client):
    # collector writes acme-tenant relationships -> acme-tenant audit record
    from eda.db import SessionLocal

    with SessionLocal() as db:
        _, secret = ingestion.register_source(
            db, source_id="okta-directory-prod", tenant_id="acme",
            provider="okta", allowed_namespace="okta:",
        )
        db.commit()
    accepted = client.post(
        "/relationship-sources/okta-directory-prod/relationships",
        json={"relationships": [
            {"subject": {"kind": "user", "id": "okta:00u1"}, "relation": "member_of",
             "target": {"kind": "group", "id": "okta:g1"}, "attributes": {}}]},
        headers=auth(secret),
    )
    assert accepted.status_code == 200

    # the local-tenant admin sees local and shared records, not acme's
    lead = make_session(client, "security-lead")
    records = client.get("/audit/records", headers=auth(lead)).json()
    tenants = {r["tenant_id"] for r in records}
    assert "acme" not in tenants
    assert not any(r["event"] == "relationship_ingest" for r in records)
    # chain integrity remains globally verifiable
    assert client.get("/audit/verify", headers=auth(lead)).json()["ok"] is True


def test_access_paths_do_not_cross_tenants(db):
    """A path that would require traversing another tenant's nodes resolves
    only when no tenant constraint conflicts."""
    from eda import access_graph

    path = access_graph.resolve_path(
        db, "derrick", "ec2:DescribeInstances", "ec2-prod-1", tenant="local"
    )
    assert path is not None
    # the same subject under a foreign tenant scope cannot use local-tenant nodes
    assert access_graph.resolve_path(
        db, "derrick", "ec2:DescribeInstances", "ec2-prod-1", tenant="acme"
    ) is None
