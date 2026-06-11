"""Authority Broker: turns an approved decision into temporary scoped authority.

Credential handling:
- Usable credential material is never persisted in the control-plane database.
  It lives in the broker's `CredentialVault`; the Grant row carries only an
  opaque `credential_ref` plus redacted metadata. (The reference vault is
  in-memory; production swaps in HashiCorp Vault / KMS-wrapped storage behind
  the same three methods.)
- Provider credential lifetime never exceeds the grant lifetime the control
  plane enforces: brokers report the provider expiry and `issue_grant` rejects
  any credential that would outlive its grant. Revoking a grant deletes the
  vault entry, so expiration/revocation stay consistent across both systems.
"""

import secrets
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from .config import settings
from .models import Grant, utcnow


class GrantError(Exception):
    pass


class CredentialVault:
    """Opaque-reference credential store. DB never sees the values."""

    def __init__(self):
        self._store: dict[str, tuple[dict, datetime]] = {}

    def put(self, credentials: dict, expires_at: datetime) -> str:
        ref = "vault-" + secrets.token_urlsafe(24)
        self._store[ref] = (credentials, expires_at)
        return ref

    def get(self, ref: str) -> dict:
        entry = self._store.get(ref)
        if entry is None:
            raise GrantError("credentials not in vault (expired, revoked, or never issued)")
        credentials, expires_at = entry
        if datetime.now(timezone.utc) > expires_at:
            del self._store[ref]
            raise GrantError("vaulted credentials expired")
        return credentials

    def revoke(self, ref: str) -> None:
        self._store.pop(ref, None)


vault = CredentialVault()


class BaseBroker(ABC):
    kind: str

    @abstractmethod
    def issue_credentials(
        self, *, subject: str, scope: dict, ttl_seconds: int, tags: dict
    ) -> tuple[dict, datetime]:
        """Return (credentials, provider_expires_at)."""


class MockStsBroker(BaseBroker):
    """Local stand-in for AWS STS. Shapes match AssumeRole output; the
    provider expiry exactly matches the requested TTL."""

    kind = "mock_sts"

    def issue_credentials(self, *, subject: str, scope: dict, ttl_seconds: int, tags: dict):
        credentials = {
            "AccessKeyId": "MOCKASIA" + secrets.token_hex(6).upper(),
            "SecretAccessKey": secrets.token_urlsafe(30),
            "SessionToken": secrets.token_urlsafe(48),
            "SessionPolicy": {"actions": scope["actions"], "resources": scope["resources"]},
            "SessionTags": tags,
        }
        return credentials, datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)


class AwsStsBroker(BaseBroker):
    """Real AWS adapter: scoped AssumeRole with an inline session policy.

    AWS enforces a 900s minimum session duration. Grants shorter than that
    are refused outright - the control plane never lets a provider credential
    outlive its grant. (Short-TTL high-risk work still flows through the
    controlled runner, where credentials are confined to the job process.)
    """

    kind = "aws_sts"

    def __init__(self, role_arn: str):
        self.role_arn = role_arn

    def issue_credentials(self, *, subject: str, scope: dict, ttl_seconds: int, tags: dict):
        if ttl_seconds < 900:
            raise GrantError(
                "AWS STS minimum session duration is 900s, which would outlive a "
                f"{ttl_seconds}s grant; raise the grant TTL"
            )
        try:
            import boto3
        except ImportError as exc:
            raise GrantError("boto3 not installed; pip install .[aws]") from exc
        import json

        session_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": scope["actions"], "Resource": scope["resources"]}
            ],
        }
        response = boto3.client("sts").assume_role(
            RoleArn=self.role_arn,
            RoleSessionName=f"eda-{subject}"[:64],
            DurationSeconds=ttl_seconds,
            Policy=json.dumps(session_policy),
            Tags=[{"Key": k, "Value": str(v)} for k, v in tags.items()],
        )
        credentials = response["Credentials"]
        return credentials, credentials["Expiration"]


_default_broker: BaseBroker = MockStsBroker()


def issue_grant(
    db: Session,
    *,
    subject: str,
    action: str,
    resource: str,
    obligations: list[dict],
    session_tags: dict,
    correlation_id: str,
    tenant_id: str | None = None,
    broker: BaseBroker | None = None,
) -> Grant:
    broker = broker or _default_broker
    ttl = settings.grant_default_ttl_seconds
    read_only = False
    for o in obligations:
        if o["type"] == "max_ttl_seconds":
            ttl = min(ttl, o["value"])
        if o["type"] == "read_only":
            read_only = True

    scope = {"actions": [action], "resources": [resource], "read_only": read_only}
    credentials, provider_expires_at = broker.issue_credentials(
        subject=subject, scope=scope, ttl_seconds=ttl, tags=session_tags
    )
    grant_expires_at = utcnow() + timedelta(seconds=ttl)
    if provider_expires_at.tzinfo is None:
        provider_expires_at = provider_expires_at.replace(tzinfo=timezone.utc)
    # Invariant: provider credential dies no later than the grant (1s slack
    # for clock arithmetic between "now" reads).
    if provider_expires_at > grant_expires_at + timedelta(seconds=1):
        raise GrantError(
            f"broker returned a credential outliving the grant "
            f"({provider_expires_at.isoformat()} > {grant_expires_at.isoformat()})"
        )

    grant = Grant(
        subject=subject,
        scope=scope,
        session_tags=session_tags,
        broker_kind=broker.kind,
        credential_ref=vault.put(credentials, provider_expires_at),
        expires_at=grant_expires_at,
        correlation_id=correlation_id,
        tenant_id=tenant_id,
    )
    db.add(grant)
    db.flush()
    return grant


def validate_grant(grant: Grant, *, action: str, resource: str) -> None:
    """Raise GrantError unless the grant is live and covers action+resource."""
    if grant.revoked:
        raise GrantError("grant revoked")
    expires = grant.expires_at
    if expires.tzinfo is None:  # SQLite round-trips naive datetimes
        expires = expires.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expires:
        raise GrantError("grant expired")
    if action not in grant.scope["actions"]:
        raise GrantError(f"action {action!r} outside grant scope")
    if resource not in grant.scope["resources"]:
        raise GrantError(f"resource {resource!r} outside grant scope")


def fetch_credentials(grant: Grant) -> dict:
    """Release vaulted credentials for execution. Callers are the action
    executor and controlled runner only - never API responses or audit."""
    if grant.revoked:
        raise GrantError("grant revoked")
    return vault.get(grant.credential_ref)


def revoke_grant(grant: Grant) -> None:
    """Revoke in both systems at once: control-plane flag + vault deletion."""
    grant.revoked = True
    vault.revoke(grant.credential_ref)


def redacted(grant: Grant) -> dict:
    """Audit-safe view: opaque reference and metadata only."""
    return {
        "grant_id": grant.id,
        "subject": grant.subject,
        "scope": grant.scope,
        "session_tags": grant.session_tags,
        "broker_kind": grant.broker_kind,
        "issued_at": grant.issued_at.isoformat(),
        "expires_at": grant.expires_at.isoformat(),
        "tenant_id": grant.tenant_id,
        "credentials": "VAULTED",
        "credential_ref": grant.credential_ref[:14] + "...",
    }
