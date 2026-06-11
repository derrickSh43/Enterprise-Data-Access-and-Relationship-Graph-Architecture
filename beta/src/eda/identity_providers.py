"""Identity providers: the trusted front of the control plane.

`IdentityProvider.verify(token) -> SessionInfo` is the only way a request
acquires an identity. Two implementations:

- `DevIdentityProvider`: the existing HMAC self-issued sessions. Tests and
  local demos only (EDA_AUTH_MODE=dev); never deploy with it.
- `OidcIdentityProvider`: validates standard OIDC bearer tokens (Okta,
  Entra ID, Keycloak, ...): JWKS signature, issuer, audience, expiry, stable
  subject, tenant, and MFA assurance from amr/acr. Callers cannot choose
  their identity, MFA status, or risk score - those come from validated
  claims (risk is server-derived and defaults to 0).

`map_principal` turns a verified session into an existing AccessNode via
issuer+subject -> tenant + canonical external ID. No mapped node, a tenant
mismatch, or a disabled/stale relationship source all fail closed.
"""

import hashlib
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import identity
from .config import settings
from .identity import InvalidSession, SessionInfo
from .models import AccessNode, RelationshipSource


class IdentityProvider(ABC):
    name: str

    @abstractmethod
    def verify(self, token: str) -> SessionInfo:
        """Return a validated session or raise InvalidSession."""


class DevIdentityProvider(IdentityProvider):
    name = "dev"

    def verify(self, token: str) -> SessionInfo:
        return identity.verify_session(token)


# ---------------------------------------------------------------------------
# OIDC
# ---------------------------------------------------------------------------
class KeySource(Protocol):
    """Resolves the signing key for a JWT. Production: remote JWKS with
    caching. Tests: a static key set."""

    def get_key(self, token: str): ...


class RemoteJwksKeySource:
    def __init__(self, jwks_url: str):
        import jwt

        self._client = jwt.PyJWKClient(jwks_url, cache_keys=True)

    def get_key(self, token: str):
        return self._client.get_signing_key_from_jwt(token).key


class StaticKeySource:
    """kid -> public key object. For tests and air-gapped setups."""

    def __init__(self, keys: dict):
        self._keys = keys

    def get_key(self, token: str):
        import jwt

        kid = jwt.get_unverified_header(token).get("kid")
        if kid not in self._keys:
            raise InvalidSession(f"unknown signing key {kid!r}")
        return self._keys[kid]


@dataclass(frozen=True)
class OidcConfig:
    issuer: str
    audience: str
    provider_prefix: str = "oidc"     # canonical external IDs become "<prefix>:<sub>"
    tenant_claim: str = "tid"
    static_tenant: str = ""           # for single-tenant providers (e.g. one Okta org)
    groups_claim: str = "groups"
    mfa_amr: frozenset = frozenset({"mfa", "otp", "hwk", "swk"})
    mfa_acr: frozenset = frozenset()
    algorithms: tuple = ("RS256", "ES256")
    leeway_seconds: int = 30


class OidcIdentityProvider(IdentityProvider):
    name = "oidc"

    def __init__(self, config: OidcConfig, key_source: KeySource):
        self.config = config
        self.key_source = key_source

    def verify(self, token: str) -> SessionInfo:
        import jwt

        cfg = self.config
        try:
            key = self.key_source.get_key(token)
            claims = jwt.decode(
                token,
                key=key,
                algorithms=list(cfg.algorithms),
                audience=cfg.audience,
                issuer=cfg.issuer,
                leeway=cfg.leeway_seconds,
                options={"require": ["exp", "iat", "sub", "iss", "aud"]},
            )
        except InvalidSession:
            raise
        except jwt.PyJWTError as exc:
            raise InvalidSession(f"oidc: {exc}")

        subject = claims["sub"]
        tenant = claims.get(cfg.tenant_claim) or cfg.static_tenant
        if not tenant:
            raise InvalidSession("oidc: token carries no tenant and no static tenant configured")

        amr = set(claims.get("amr") or [])
        mfa = bool(amr & cfg.mfa_amr) or (claims.get("acr") in cfg.mfa_acr)

        groups = claims.get(cfg.groups_claim) or []
        if not isinstance(groups, list):
            groups = [groups]

        session_id = (
            claims.get("sid")
            or claims.get("jti")
            or hashlib.sha256(token.encode()).hexdigest()[:32]
        )
        return SessionInfo(
            session_id=session_id,
            subject=subject,
            mfa=mfa,
            risk_score=0,  # server-derived only; never caller-supplied
            tags={"iss": cfg.issuer, "tenant": tenant},
            expires_at=float(claims["exp"]),
            issuer=cfg.issuer,
            tenant=tenant,
            external_id=f"{cfg.provider_prefix}:{subject}",
            groups=tuple(groups),
        )


# ---------------------------------------------------------------------------
# Provider selection
# ---------------------------------------------------------------------------
_override: IdentityProvider | None = None
_oidc_cached: IdentityProvider | None = None


def set_identity_provider(provider: IdentityProvider | None) -> None:
    """Explicit wiring hook (tests, custom deployments). None resets."""
    global _override
    _override = provider


def get_identity_provider() -> IdentityProvider:
    global _oidc_cached
    if _override is not None:
        return _override
    if settings.auth_mode == "oidc":
        if _oidc_cached is None:
            if not (settings.oidc_issuer and settings.oidc_audience and settings.oidc_jwks_url):
                raise RuntimeError(
                    "EDA_AUTH_MODE=oidc requires EDA_OIDC_ISSUER, EDA_OIDC_AUDIENCE, "
                    "and EDA_OIDC_JWKS_URL"
                )
            _oidc_cached = OidcIdentityProvider(
                OidcConfig(
                    issuer=settings.oidc_issuer,
                    audience=settings.oidc_audience,
                    provider_prefix=settings.oidc_provider_prefix,
                    tenant_claim=settings.oidc_tenant_claim,
                    static_tenant=settings.oidc_static_tenant,
                    groups_claim=settings.oidc_groups_claim,
                    mfa_amr=frozenset(
                        v.strip() for v in settings.oidc_mfa_amr.split(",") if v.strip()
                    ),
                    mfa_acr=frozenset(
                        v.strip() for v in settings.oidc_mfa_acr.split(",") if v.strip()
                    ),
                ),
                RemoteJwksKeySource(settings.oidc_jwks_url),
            )
        return _oidc_cached
    return DevIdentityProvider()


# ---------------------------------------------------------------------------
# Identity -> graph principal (fail closed)
# ---------------------------------------------------------------------------
def _aware(ts: datetime | None) -> datetime | None:
    if ts is not None and ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts


def map_principal(db: Session, session: SessionInfo) -> AccessNode | None:
    """Resolve a verified session to an existing AccessNode, or None (deny).

    Fail-closed conditions: no node carries the session's external ID; the
    node's tenant differs from the token's; the node was asserted by a
    relationship source that is unknown, disabled, or stale; or the node is
    seeded (no source) while the session is not a dev session.
    """
    if not session.external_id:
        return None
    node = db.scalar(select(AccessNode).where(AccessNode.external_id == session.external_id))
    if node is None or node.kind != "user":
        return None
    if session.tenant and node.tenant_id and node.tenant_id != session.tenant:
        return None

    if node.source_id is None:
        # Seeded principal: honored only for dev sessions (tests/local demos).
        return node if session.issuer == "dev" else None

    source = db.get(RelationshipSource, node.source_id)
    if source is None or not source.enabled:
        return None
    last_sync = _aware(source.last_sync_at)
    if last_sync is None:
        return None
    age = datetime.now(timezone.utc) - last_sync
    if age.total_seconds() > settings.source_max_age_seconds:
        return None
    return node
