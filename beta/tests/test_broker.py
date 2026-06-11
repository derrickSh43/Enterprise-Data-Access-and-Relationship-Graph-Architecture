from datetime import timedelta

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


def test_revoked_grant_rejected(db):
    grant = issue(db)
    grant.revoked = True
    with pytest.raises(broker.GrantError, match="revoked"):
        broker.validate_grant(grant, action="ec2:DescribeInstances", resource="ec2-prod-1")


def test_redacted_view_never_contains_credentials(db):
    grant = issue(db)
    view = broker.redacted(grant)
    assert view["credentials"] == "REDACTED"
    secret = grant.credentials["SecretAccessKey"]
    assert secret not in str(view)
