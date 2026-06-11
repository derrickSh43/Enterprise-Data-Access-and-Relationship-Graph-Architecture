from datetime import datetime, timedelta, timezone

import pytest

from eda import broker
from eda.models import utcnow


def issue(db, **kwargs):
    defaults = dict(
        subject="derrick",
        action="ec2:DescribeInstances",
        resource="ec2-prod-1",
        obligations=[{"type": "max_ttl_seconds", "value": 300}, {"type": "read_only"}],
        session_tags={"session_id": "s1"},
        correlation_id="c1",
    )
    defaults.update(kwargs)
    return broker.issue_grant(db, **defaults)


def test_grant_is_short_lived_and_scoped(db):
    grant = issue(db)
    assert grant.scope == {
        "actions": ["ec2:DescribeInstances"],
        "resources": ["ec2-prod-1"],
        "read_only": True,
    }
    # obligation TTL (300s) wins over the 900s default
    assert (grant.expires_at - grant.issued_at) <= timedelta(seconds=301)
    broker.validate_grant(grant, action="ec2:DescribeInstances", resource="ec2-prod-1")


def test_expired_grant_rejected(db):
    grant = issue(db)
    grant.expires_at = utcnow() - timedelta(seconds=1)
    with pytest.raises(broker.GrantError, match="expired"):
        broker.validate_grant(grant, action="ec2:DescribeInstances", resource="ec2-prod-1")


def test_out_of_scope_action_and_resource_rejected(db):
    grant = issue(db)
    with pytest.raises(broker.GrantError, match="outside grant scope"):
        broker.validate_grant(grant, action="ec2:TerminateInstances", resource="ec2-prod-1")
    with pytest.raises(broker.GrantError, match="outside grant scope"):
        broker.validate_grant(grant, action="ec2:DescribeInstances", resource="ec2-prod-2")


def test_revoked_grant_rejected_and_vault_cleared(db):
    grant = issue(db)
    broker.revoke_grant(grant)
    with pytest.raises(broker.GrantError, match="revoked"):
        broker.validate_grant(grant, action="ec2:DescribeInstances", resource="ec2-prod-1")
    with pytest.raises(broker.GrantError, match="revoked"):
        broker.fetch_credentials(grant)


def test_credentials_never_persisted_only_vault_reference(db):
    grant = issue(db)
    # the ORM row carries only an opaque reference
    assert grant.credential_ref.startswith("vault-")
    assert not hasattr(grant, "credentials")
    credentials = broker.fetch_credentials(grant)
    assert credentials["AccessKeyId"].startswith("MOCKASIA")
    # redacted view: no credential material, truncated reference only
    view = broker.redacted(grant)
    assert view["credentials"] == "VAULTED"
    assert credentials["SecretAccessKey"] not in str(view)
    assert grant.credential_ref not in str(view)


def test_vaulted_credentials_expire_with_provider_lifetime(db):
    grant = issue(db)
    # force vault expiry
    creds, _ = broker.vault._store[grant.credential_ref]
    broker.vault._store[grant.credential_ref] = (
        creds, datetime.now(timezone.utc) - timedelta(seconds=1)
    )
    with pytest.raises(broker.GrantError, match="expired"):
        broker.fetch_credentials(grant)


def test_provider_credential_may_not_outlive_grant(db):
    class LongLivedBroker(broker.BaseBroker):
        kind = "long_lived"

        def issue_credentials(self, *, subject, scope, ttl_seconds, tags):
            return {"AccessKeyId": "X"}, datetime.now(timezone.utc) + timedelta(hours=12)

    with pytest.raises(broker.GrantError, match="outliving the grant"):
        issue(db, broker=LongLivedBroker())


def test_aws_broker_refuses_grants_below_provider_minimum(db):
    aws = broker.AwsStsBroker(role_arn="arn:aws:iam::123:role/x")
    with pytest.raises(broker.GrantError, match="minimum session duration"):
        aws.issue_credentials(
            subject="derrick", scope={"actions": [], "resources": []},
            ttl_seconds=300, tags={},
        )
