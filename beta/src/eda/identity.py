"""Identity layer: stateless HMAC-signed session tokens.

Stands in for SSO (OIDC/SAML). The token carries the claims the rest of the
control plane needs: subject, MFA presence, session risk score, session tags.
In production this module is replaced by an IdP integration; everything
downstream only depends on `SessionInfo`.
"""

import base64
import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass

from .config import settings


class InvalidSession(Exception):
    pass


@dataclass(frozen=True)
class SessionInfo:
    session_id: str
    subject: str
    mfa: bool
    risk_score: int
    tags: dict
    expires_at: float
    # Identity provenance: which provider asserted this session and the
    # canonical external ID it maps to in the access graph (fail closed if no
    # AccessNode carries that external_id).
    issuer: str = "dev"
    tenant: str | None = "local"
    external_id: str | None = None
    groups: tuple = ()


def _sign(payload_b64: bytes) -> str:
    return hmac.new(settings.token_secret.encode(), payload_b64, hashlib.sha256).hexdigest()


def issue_session(
    subject: str,
    *,
    mfa: bool,
    risk_score: int = 0,
    tags: dict | None = None,
    ttl_seconds: int | None = None,
) -> str:
    payload = {
        "sid": uuid.uuid4().hex,
        "sub": subject,
        "mfa": mfa,
        "risk": risk_score,
        "tags": tags or {},
        "exp": time.time() + (ttl_seconds or settings.session_ttl_seconds),
    }
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload, sort_keys=True).encode())
    return f"{payload_b64.decode()}.{_sign(payload_b64)}"


def verify_session(token: str) -> SessionInfo:
    try:
        payload_b64, sig = token.rsplit(".", 1)
    except ValueError:
        raise InvalidSession("malformed token")
    if not hmac.compare_digest(_sign(payload_b64.encode()), sig):
        raise InvalidSession("bad signature")
    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    if time.time() > payload["exp"]:
        raise InvalidSession("session expired")
    return SessionInfo(
        session_id=payload["sid"],
        subject=payload["sub"],
        mfa=payload["mfa"],
        risk_score=payload["risk"],
        tags=payload["tags"],
        expires_at=payload["exp"],
        issuer="dev",
        tenant="local",
        external_id=f"dev:{payload['sub']}",
    )
