import pytest

from eda import broker, objects


def grant_for(db, resource, *, read_only=True, action="ec2:DescribeInstances"):
    obligations = [{"type": "read_only"}] if read_only else []
    return broker.issue_grant(
        db,
        subject="derrick",
        action=action,
        resource=resource,
        obligations=obligations,
        session_tags={},
        correlation_id="c1",
    )


def test_context_requires_valid_grant(db):
    from datetime import timedelta

    from eda.models import utcnow

    grant = grant_for(db, "ec2-prod-1")
    grant.expires_at = utcnow() - timedelta(seconds=1)
    with pytest.raises(broker.GrantError):
        objects.scoped_context(db, grant=grant, resource="ec2-prod-1")


def test_context_is_scoped_to_neighborhood(db):
    grant = grant_for(db, "ec2-prod-1")
    context = objects.scoped_context(db, grant=grant, resource="ec2-prod-1", max_hops=2)
    names = {n["name"] for n in context["nodes"]}
    assert {"ec2-prod-1", "payments-api", "vpc-prod", "F-2026-0142"} <= names
    # cardholder-data is 4 hops out - beyond scope
    assert "cardholder-data" not in names


def test_sensitive_neighbors_redacted_under_read_only_grant(db):
    grant = grant_for(db, "ec2-prod-1")
    context = objects.scoped_context(db, grant=grant, resource="ec2-prod-1", max_hops=2)
    secret_node = next(n for n in context["nodes"] if n["name"] == "db-creds-prod")
    assert "REDACTED" in str(secret_node["attrs"])
