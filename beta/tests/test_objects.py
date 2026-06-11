"""Per-node disclosure: root authority does not extend to everything connected."""

import pytest

from eda import broker, objects


def grant_for(db, resource, *, read_only=True, action="ec2:DescribeInstances", tenant="local"):
    obligations = [{"type": "read_only"}] if read_only else []
    return broker.issue_grant(
        db,
        subject="derrick",
        action=action,
        resource=resource,
        obligations=obligations,
        session_tags={},
        correlation_id="c1",
        tenant_id=tenant,
    )


def context_for(db, resource, **kwargs):
    grant = grant_for(db, resource, **kwargs)
    return objects.scoped_context(db, grant=grant, resource=resource, max_hops=2)


def test_context_requires_valid_grant(db):
    from datetime import timedelta

    from eda.models import utcnow

    grant = grant_for(db, "ec2-prod-1")
    grant.expires_at = utcnow() - timedelta(seconds=1)
    with pytest.raises(broker.GrantError):
        objects.scoped_context(db, grant=grant, resource="ec2-prod-1")


def test_context_is_scoped_to_neighborhood(db):
    context = context_for(db, "ec2-prod-1")
    names = {n["name"] for n in context["nodes"]}
    assert {"ec2-prod-1", "payments-api", "vpc-prod", "F-2026-0142"} <= names
    # cardholder-data is 4 hops out - beyond scope
    assert "cardholder-data" not in names


def test_root_gets_full_attrs_including_restricted_fields(db):
    context = context_for(db, "ec2-prod-1")
    root = next(n for n in context["nodes"] if n["name"] == "ec2-prod-1")
    assert root["attrs"]["region"] == "us-east-1"  # full view: grant covers the root


def test_sensitive_node_beyond_one_hop_is_omitted_entirely(db):
    # db-creds-prod sits 2 hops from ec2-prod-1 (via payments-api): omitted,
    # along with its edges - root authority does not enumerate distant secrets
    context = context_for(db, "ec2-prod-1")
    names = {n["name"] for n in context["nodes"]}
    assert "db-creds-prod" not in names
    assert not any("db-creds-prod" in e["src"] + e["dst"] for e in context["edges"])


def test_sensitive_neighbor_at_one_hop_listed_but_redacted(db):
    # from payments-api, the secret is 1 hop: visible as a relationship,
    # attributes redacted
    context = context_for(db, "payments-api")
    secret = next(n for n in context["nodes"] if n["name"] == "db-creds-prod")
    assert "REDACTED" in str(secret["attrs"])
    assert secret["distance"] == 1


def test_restricted_fields_redacted_on_non_root_nodes(db):
    context = context_for(db, "payments-api")
    instance = next(n for n in context["nodes"] if n["name"] == "ec2-prod-1")
    assert instance["attrs"]["region"] == "REDACTED"  # restricted field, non-root view
    assert instance["attrs"]["environment"] == "production"  # unrestricted fields intact


def test_objects_of_other_tenants_are_invisible(db):
    objects.add_object(db, "database", "acme-db", {"classification": "internal"},
                       tenant_id="acme")
    other_app = objects.get_object(db, "application", "payments-api")
    acme_db = objects.get_object(db, "database", "acme-db")
    objects.relate(db, other_app, "uses", acme_db)

    context = context_for(db, "payments-api", tenant="local")
    assert "acme-db" not in {n["name"] for n in context["nodes"]}
