from eda.db import SessionLocal
from eda.models import RelationshipSource, AuditRecord
from sqlalchemy import select

BODY = {"source_id": "entra", "provider": "entra", "allowed_namespace": ""}
def auth(client, who):
    token = client.post("/identity/sessions", json={"subject": who}).json()["session_token"]
    return {"Authorization": "Bearer " + token}

def test_source_bootstrap_is_admin_only_and_tenant_bound(client):
    assert client.post("/relationship-sources", json=BODY).status_code == 401
    assert client.post("/relationship-sources", json=BODY, headers=auth(client, "derrick")).status_code == 403
    headers = auth(client, "security-lead")
    assert client.post("/relationship-sources", json={**BODY, "tenant_id": "foreign"}, headers=headers).status_code == 422
    result = client.post("/relationship-sources", json=BODY, headers=headers)
    assert result.status_code == 201
    assert result.headers["Cache-Control"] == "no-store"
    secret = result.json()["collector_token"]
    with SessionLocal() as db:
        source = db.get(RelationshipSource, "entra")
        assert source.tenant_id == "local"
        assert secret not in source.collector_identity
        records = db.scalars(select(AuditRecord)).all()
        assert all(secret not in str(r.context_summary) for r in records)
    assert client.post("/relationship-sources", json=BODY, headers=headers).status_code == 409
    assert client.get("/relationship-sources/entra/sync-state", headers={"Authorization": "Bearer wrong"}).status_code == 403
    manifest = {"connector_type": "entra", "object_kinds": ["user", "group"], "relations": ["member_of"], "capabilities": ["snapshot"]}
    assert client.post("/relationship-sources/entra/manifest", json=manifest, headers=headers).status_code == 200
    state = client.get("/relationship-sources/entra/sync-state", headers={"Authorization": "Bearer " + secret})
    assert state.status_code == 200
    assert state.json()["sequence"] == 0
