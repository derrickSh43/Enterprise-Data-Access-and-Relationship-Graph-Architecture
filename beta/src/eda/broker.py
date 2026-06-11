"""Authority Broker: turns an approved decision into temporary scoped authority.

Prefers short-lived, scoped, auditable access over standing privilege. Locally
this issues mock STS-shaped credentials; the `AwsStsBroker` adapter shows where
real `sts:AssumeRole` with a session policy plugs in (GCP impersonation and
Azure PIM adapters follow the same interface).

Credentials are stored on the Grant for the executor; audit records only ever
see `redacted()`. For actions with the `controlled_runner` obligation the
credentials never leave the action layer at all.
"""

import secrets
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from .config import settings
from .models import Grant, utcnow


class GrantError(Exception):
    pass


class BaseBroker(ABC):
    kind: str

    @abstractmethod
    def issue_credentials(self, *, subject: str, scope: dict, ttl_seconds: int, tags: dict) -> dict:
        ...


class MockStsBroker(BaseBroker):
    """Local stand-in for AWS STS. Shapes match AssumeRole output."""

    kind = "mock_sts"

    def issue_credentials(self, *, subject: str, scope: dict, ttl_seconds: int, tags: dict) -> dict:
        return {
            "AccessKeyId": "MOCKASIA" + secrets.token_hex(6).upper(),
            "SecretAccessKey": secrets.token_urlsafe(30),
            "SessionToken": secrets.token_urlsafe(48),
            "SessionPolicy": {"actions": scope["actions"], "resources": scope["resources"]},
            "SessionTags": tags,
        }


class AwsStsBroker(BaseBroker):
    """Real AWS adapter: scoped AssumeRole with an inline session policy.

    Requires `pip install .[aws]` plus a configured role ARN; included to show
    the integration seam, not exercised by the local demo or tests.
    """

    kind = "aws_sts"

    def __init__(self, role_arn: str):
        self.role_arn = role_arn

    def issue_credentials(self, *, subject: str, scope: dict, ttl_seconds: int, tags: dict) -> dict:
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
            DurationSeconds=max(900, ttl_seconds),
            Policy=json.dumps(session_policy),
            Tags=[{"Key": k, "Value": str(v)} for k, v in tags.items()],
        )
        return response["Credentials"]


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
    credentials = broker.issue_credentials(
        subject=subject, scope=scope, ttl_seconds=ttl, tags=session_tags
    )
    grant = Grant(
        subject=subject,
        scope=scope,
        session_tags=session_tags,
        broker_kind=broker.kind,
        credentials=credentials,
        expires_at=utcnow() + timedelta(seconds=ttl),
        correlation_id=correlation_id,
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


def redacted(grant: Grant) -> dict:
    """Audit-safe view: everything except credential material."""
    return {
        "grant_id": grant.id,
        "subject": grant.subject,
        "scope": grant.scope,
        "session_tags": grant.session_tags,
        "broker_kind": grant.broker_kind,
        "issued_at": grant.issued_at.isoformat(),
        "expires_at": grant.expires_at.isoformat(),
        "credentials": "REDACTED",
    }
