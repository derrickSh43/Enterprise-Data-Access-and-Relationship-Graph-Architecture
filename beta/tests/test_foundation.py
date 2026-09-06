"""Regression tests for fail-closed configuration, identity and unknown risk."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from eda import api, identity_providers, policy
from eda.config import Settings
from eda.models import AccessNode
from test_identity_mapping import ingest_okta_user, oidc_session
from test_oidc import make_token, signing_key, provider
from test_policy import make_input


@pytest.mark.parametrize("fields", [
    {"environment": "prod"}, {"auth_mode": "odic"},
    {"environment": "production", "auth_mode": "dev"},
    {"grant_default_ttl_seconds": 0}, {"source_max_age_seconds": -1},
    {"auth_mode": "oidc"},
])
def test_invalid_settings_rejected(fields):
    with pytest.raises(ValueError):
        replace(Settings(), **fields).validate()


def test_production_remains_release_gated():
    cfg = replace(Settings(), environment="production", auth_mode="oidc",
                  oidc_issuer="https://idp.example.com", oidc_jwks_url="https://idp.example.com/keys",
                  oidc_audience="eda")
    with pytest.raises(ValueError, match="not qualified"):
        cfg.validate()


def test_bad_configuration_rejected_before_database_init(monkeypatch):
    monkeypatch.setattr(api, "settings", replace(Settings(), auth_mode="typo"))
    monkeypatch.setattr(api, "init_db", lambda: pytest.fail("database touched before validation"))
    with pytest.raises(ValueError, match="EDA_AUTH_MODE"):
        with TestClient(api.app):
            pass


def test_oidc_startup_never_seeds_demo(monkeypatch):
    cfg = replace(Settings(), auth_mode="oidc", oidc_issuer="https://idp.example.com",
                  oidc_jwks_url="https://idp.example.com/keys", oidc_audience="eda")
    monkeypatch.setattr(api, "settings", cfg)
    monkeypatch.setattr(api, "get_identity_provider", lambda: object())
    monkeypatch.setattr(api, "init_db", lambda: None)
    monkeypatch.setattr(api, "seed", lambda db: pytest.fail("demo seeding in OIDC mode"))
    with TestClient(api.app) as client:
        assert client.post("/identity/sessions", json={"subject": "derrick"}).status_code == 403


def test_auth_typo_never_falls_back(monkeypatch):
    monkeypatch.setattr(identity_providers, "settings", replace(Settings(), auth_mode="typo"))
    with pytest.raises(RuntimeError):
        identity_providers.get_identity_provider()


@pytest.mark.parametrize("claims", [
    {"tid": "other-tenant"}, {"tid": ["acme"]}, {"amr": "mfa"},
    {"amr": [["mfa"]]}, {"acr": []}, {"groups": "admins"}, {"sid": 42},
    {"sub": ""},
])
def test_malformed_or_wrong_tenant_claims_rejected(provider, signing_key, claims):
    with pytest.raises(identity_providers.InvalidSession):
        provider.verify(make_token(signing_key, **claims))


def test_token_risk_claim_does_not_establish_trusted_risk(provider, signing_key):
    assert provider.verify(make_token(signing_key, risk_score=0)).risk_score is None


def test_single_factor_is_not_default_mfa(signing_key):
    from test_oidc import ISSUER, AUDIENCE, KID
    provider = identity_providers.OidcIdentityProvider(
        identity_providers.OidcConfig(issuer=ISSUER, audience=AUDIENCE, static_tenant="acme"),
        identity_providers.StaticKeySource({KID: signing_key.public_key()}))
    assert not provider.verify(make_token(signing_key, amr=["otp"])).mfa


def test_mapping_uses_tenant_and_rejects_ambiguity(db):
    ingest_okta_user(db)
    db.add(AccessNode(kind="user", name="foreign", external_id="okta:00u123", tenant_id="other"))
    db.flush()
    assert identity_providers.map_principal(db, oidc_session()).tenant_id == "acme"
    db.add(AccessNode(kind="user", name="duplicate", external_id="okta:00u123", tenant_id="acme"))
    db.flush()
    assert identity_providers.map_principal(db, oidc_session()) is None


def test_mapping_rejects_source_tenant_mismatch_and_future_sync(db):
    source = ingest_okta_user(db)
    source.tenant_id = "other"
    db.flush()
    assert identity_providers.map_principal(db, oidc_session()) is None
    source.tenant_id = "acme"
    source.last_sync_at = datetime.now(timezone.utc) + timedelta(hours=1)
    db.flush()
    assert identity_providers.map_principal(db, oidc_session()) is None


def test_unknown_risk_allows_only_non_sensitive_read(db):
    request = make_input(session={"mfa": True, "risk_score": None})
    assert policy.evaluate(db, request).decision == "allowed"
    request["action"]["read_only"] = False
    request["approval_present"] = True
    assert policy.evaluate(db, request).decision == "denied"
    request["action"]["read_only"] = True
    request["resource"]["classification"] = "sensitive"
    assert policy.evaluate(db, request).decision == "denied"


def test_missing_production_policy_does_not_create_default(db, monkeypatch):
    from sqlalchemy import delete
    from eda.models import PolicyRecord
    db.execute(delete(PolicyRecord))
    monkeypatch.setattr(policy, "settings", replace(Settings(), environment="production"))
    with pytest.raises(policy.PolicyError, match="explicitly activated"):
        policy.active_policy(db)


def test_explicit_issuer_directory_binding(db, monkeypatch):
    session = oidc_session()
    source = ingest_okta_user(db)
    node = db.scalar(__import__("sqlalchemy").select(AccessNode).where(AccessNode.external_id == session.external_id))
    node.external_id = "00u123"
    db.flush()
    monkeypatch.setattr(identity_providers, "settings", replace(Settings(),
        oidc_directory_source=source.id, oidc_issuer=session.issuer, oidc_provider_prefix="okta"))
    assert identity_providers.map_principal(db, session).id == node.id
    # Same native ID in another directory cannot replace the pinned authority.
    from eda.ingestion import register_source
    other, _ = register_source(db, source_id="other-dir", tenant_id="acme", provider="other", allowed_namespace="")
    other.last_sync_at = datetime.now(timezone.utc)
    db.add(AccessNode(kind="user", name="impostor", external_id="00u123", tenant_id="acme",
                      source_id=other.id, observed_at=datetime.now(timezone.utc)))
    db.flush()
    assert identity_providers.map_principal(db, session).id == node.id
    source.enabled = False
    db.flush()
    assert identity_providers.map_principal(db, session) is None
    source.enabled = True
    monkeypatch.setattr(identity_providers, "settings", replace(Settings(),
        oidc_directory_source=source.id, oidc_issuer="https://wrong.example", oidc_provider_prefix="okta"))
    assert identity_providers.map_principal(db, session) is None
