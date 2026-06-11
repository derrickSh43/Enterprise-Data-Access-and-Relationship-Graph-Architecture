"""OIDC verification: JWKS signature, issuer, audience, expiry, tenant, MFA."""

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from eda.identity import InvalidSession
from eda.identity_providers import OidcConfig, OidcIdentityProvider, StaticKeySource

ISSUER = "https://idp.example.com"
AUDIENCE = "eda-control-plane"
KID = "test-key-1"


@pytest.fixture(scope="module")
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def provider(signing_key):
    return OidcIdentityProvider(
        OidcConfig(
            issuer=ISSUER,
            audience=AUDIENCE,
            provider_prefix="okta",
            static_tenant="acme",
            mfa_amr=frozenset({"mfa", "otp"}),
        ),
        StaticKeySource({KID: signing_key.public_key()}),
    )


def make_token(signing_key, *, kid=KID, **overrides):
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "00u123",
        "iat": now,
        "exp": now + 600,
        "amr": ["pwd", "mfa"],
        "groups": ["security-engineers"],
        "sid": "okta-session-1",
    }
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": kid})


def test_valid_token_yields_mapped_session(provider, signing_key):
    session = provider.verify(make_token(signing_key))
    assert session.subject == "00u123"
    assert session.external_id == "okta:00u123"
    assert session.tenant == "acme"
    assert session.issuer == ISSUER
    assert session.mfa is True
    assert session.risk_score == 0  # server-derived, never caller-supplied
    assert "security-engineers" in session.groups


def test_forged_signature_rejected(provider):
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = make_token(attacker_key)  # same kid, wrong key
    with pytest.raises(InvalidSession):
        provider.verify(forged)


def test_unknown_kid_rejected(provider, signing_key):
    with pytest.raises(InvalidSession, match="unknown signing key"):
        provider.verify(make_token(signing_key, kid="rogue-kid"))


def test_expired_token_rejected(provider, signing_key):
    token = make_token(signing_key, exp=int(time.time()) - 600)
    with pytest.raises(InvalidSession):
        provider.verify(token)


def test_wrong_audience_rejected(provider, signing_key):
    with pytest.raises(InvalidSession):
        provider.verify(make_token(signing_key, aud="some-other-app"))


def test_wrong_issuer_rejected(provider, signing_key):
    with pytest.raises(InvalidSession):
        provider.verify(make_token(signing_key, iss="https://evil.example.com"))


def test_missing_required_claims_rejected(provider, signing_key):
    with pytest.raises(InvalidSession):
        provider.verify(make_token(signing_key, sub=None))


def test_no_mfa_assurance_means_mfa_false(provider, signing_key):
    session = provider.verify(make_token(signing_key, amr=["pwd"]))
    assert session.mfa is False  # the policy engine then denies brokered access


def test_tenant_claim_over_static(signing_key):
    provider = OidcIdentityProvider(
        OidcConfig(issuer=ISSUER, audience=AUDIENCE, provider_prefix="entra",
                   tenant_claim="tid"),
        StaticKeySource({KID: signing_key.public_key()}),
    )
    session = provider.verify(make_token(signing_key, tid="tenant-guid-1"))
    assert session.tenant == "tenant-guid-1"
    # and with neither claim nor static tenant, fail closed
    with pytest.raises(InvalidSession, match="tenant"):
        provider.verify(make_token(signing_key))
