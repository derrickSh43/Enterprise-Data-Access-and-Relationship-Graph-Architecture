"""Identity-to-graph mapping: issuer+subject -> tenant + external ID ->
existing AccessNode, failing closed everywhere it should."""

import time
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from eda import identity, ingestion
from eda.config import settings
from eda.identity import SessionInfo
from eda.identity_providers import (
    DevIdentityProvider,
    OidcConfig,
    OidcIdentityProvider,
    StaticKeySource,
    map_principal,
    set_identity_provider,
)

ISSUER = "https://idp.example.com"
AUDIENCE = "eda-control-plane"
KID = "kid-1"
SECRET = "collector-s3cret"


def oidc_session(**overrides):
    fields = dict(
        session_id="s1", subject="00u123", mfa=True, risk_score=0, tags={},
        expires_at=time.time() + 600, issuer=ISSUER, tenant="acme",
        external_id="okta:00u123",
    )
    fields.update(overrides)
    return SessionInfo(**fields)


def ingest_okta_user(db, **source_overrides):
    fields = dict(source_id="okta-directory-prod", tenant_id="acme", provider="okta",
                  allowed_namespace="okta:", secret=SECRET)
    fields.update(source_overrides)
    source, _ = ingestion.register_source(db, **fields)
    ingestion.ingest(db, source=source, relationships=[{
        "subject": {"kind": "user", "id": "okta:00u123"},
        "relation": "member_of",
        "target": {"kind": "group", "id": "okta:g-sec"},
        "attributes": {},
    }])
    db.commit()
    return source


def test_dev_session_maps_to_seeded_principal(db):
    session = DevIdentityProvider().verify(identity.issue_session("derrick", mfa=True))
    principal = map_principal(db, session)
    assert principal is not None and principal.name == "derrick"


def test_oidc_session_maps_to_imported_principal(db):
    ingest_okta_user(db)
    principal = map_principal(db, oidc_session())
    assert principal is not None
    assert principal.external_id == "okta:00u123"


def test_unknown_identity_fails_closed(db):
    assert map_principal(db, oidc_session(external_id="okta:never-imported")) is None


def test_tenant_mismatch_fails_closed(db):
    ingest_okta_user(db)
    assert map_principal(db, oidc_session(tenant="other-tenant")) is None


def test_seeded_principal_not_honored_for_oidc_sessions(db):
    # derrick is seeded (no source); an OIDC token claiming dev:derrick must not map
    session = oidc_session(external_id="dev:derrick", tenant="local")
    assert map_principal(db, session) is None


def test_disabled_source_fails_closed(db):
    source = ingest_okta_user(db)
    assert map_principal(db, oidc_session()) is not None
    source.enabled = False
    db.commit()
    assert map_principal(db, oidc_session()) is None


def test_stale_source_fails_closed(db):
    source = ingest_okta_user(db)
    source.last_sync_at = datetime.now(timezone.utc) - timedelta(
        seconds=settings.source_max_age_seconds + 60
    )
    db.commit()
    assert map_principal(db, oidc_session()) is None


def test_non_user_node_does_not_map(db):
    ingest_okta_user(db)
    assert map_principal(db, oidc_session(external_id="okta:g-sec")) is None


# ---------------------------------------------------------------------------
# OIDC end to end: Okta-style token through /requests, downstream unchanged
# ---------------------------------------------------------------------------
@pytest.fixture()
def oidc_wired(client):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    provider = OidcIdentityProvider(
        OidcConfig(issuer=ISSUER, audience=AUDIENCE, provider_prefix="okta",
                   static_tenant="acme"),
        StaticKeySource({KID: key.public_key()}),
    )
    set_identity_provider(provider)
    try:
        yield client, key
    finally:
        set_identity_provider(None)


def make_token(key, **overrides):
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": "00u123", "iat": now,
              "exp": now + 600, "amr": ["mfa"]}
    claims.update(overrides)
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": KID})


FULL_PATH = [
    {"subject": {"kind": "user", "id": "okta:00u123"}, "relation": "member_of",
     "target": {"kind": "group", "id": "okta:g-sec"}, "attributes": {}},
    {"subject": {"kind": "group", "id": "okta:g-sec"}, "relation": "assigned",
     "target": {"kind": "permission_set", "id": "okta:ps-ro"}, "attributes": {}},
    {"subject": {"kind": "permission_set", "id": "okta:ps-ro"}, "relation": "can_assume",
     "target": {"kind": "role", "id": "okta:r-audit"}, "attributes": {}},
    {"subject": {"kind": "role", "id": "okta:r-audit"}, "relation": "role_allows",
     "target": {"kind": "account", "id": "okta:acct-prod"},
     "attributes": {"actions": ["ec2:Describe*"]}},
    {"subject": {"kind": "account", "id": "okta:acct-prod"}, "relation": "account_contains",
     "target": {"kind": "asset", "id": "okta:i-0abc"}, "attributes": {}},
]


def test_okta_token_through_unchanged_request_flow(oidc_wired):
    client, key = oidc_wired
    from eda.db import SessionLocal

    with SessionLocal() as db:
        source, secret = ingestion.register_source(
            db, source_id="okta-directory-prod", tenant_id="acme",
            provider="okta", allowed_namespace="okta:",
        )
        ingestion.ingest(db, source=source, relationships=FULL_PATH)
        db.commit()

    # view_asset is kind-agnostic; okta:i-0abc is not modeled in the object
    # graph, so kind-restricted actions would be rejected as incompatible
    trace = client.post(
        "/requests",
        json={"action": "view_asset", "resource": "okta:i-0abc"},
        headers={"Authorization": f"Bearer {make_token(key)}"},
    ).json()
    assert trace["outcome"] == "allowed"
    assert trace["stages"]["identity"]["external_id"] == "okta:00u123"
    assert trace["stages"]["identity"]["mfa"] is True
    assert trace["stages"]["grant"]["credentials"] == "VAULTED"

    # forged token: fail closed at the front
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = client.post(
        "/requests",
        json={"action": "view_asset", "resource": "okta:i-0abc"},
        headers={"Authorization": f"Bearer {make_token(attacker)}"},
    ).json()
    assert forged["outcome"] == "denied"
    assert "identity" in forged["error"]

    # valid token but unknown identity: fail closed at mapping
    unknown = client.post(
        "/requests",
        json={"action": "view_asset", "resource": "okta:i-0abc"},
        headers={"Authorization": f"Bearer {make_token(key, sub='00u-never-seen')}"},
    ).json()
    assert unknown["outcome"] == "denied"
    assert "no mapped graph principal" in unknown["error"]

    # token without MFA assurance: existing policy engine denies, unchanged
    no_mfa = client.post(
        "/requests",
        json={"action": "view_asset", "resource": "okta:i-0abc"},
        headers={"Authorization": f"Bearer {make_token(key, amr=['pwd'])}"},
    ).json()
    assert no_mfa["outcome"] == "denied"
    assert "MFA" in no_mfa["error"]


def test_dev_session_endpoint_disabled_outside_dev_mode(client):
    object.__setattr__(settings, "auth_mode", "oidc")
    try:
        response = client.post("/identity/sessions", json={"subject": "derrick"})
        assert response.status_code == 403
    finally:
        object.__setattr__(settings, "auth_mode", "dev")
