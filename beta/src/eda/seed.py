"""Seed data mirroring the architecture doc's example environment.

Access graph:
    user:derrick -> member_of group:security-engineers
                 -> assigned permission_set:prod-readonly
                 -> can_assume role:prod-security-auditor
                 -> role_allows ec2:Describe* on account:prod
                 -> account_contains asset:ec2-prod-1

Plus a second (privileged) path via permission_set:prod-secops for secret
rotation / containment, a user with a path but weak sessions (marcus), and a
contractor with no path at all (eve).
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import access_graph as ag
from . import objects as og
from . import policy
from .models import AccessNode


def seed(db: Session) -> None:
    if db.scalar(select(AccessNode).limit(1)) is not None:
        return  # already seeded

    # ---- Access Graph -----------------------------------------------------
    # Seeded principals are dev-only: external_id "dev:<name>" maps the dev
    # identity provider's sessions; OIDC sessions never resolve to these.
    def dev_user(name: str, attrs: dict):
        return ag.add_node(
            db, "user", name, attrs, tenant_id="local", external_id=f"dev:{name}"
        )

    derrick = dev_user("derrick", {"title": "security engineer"})
    marcus = dev_user("marcus", {"title": "security engineer"})
    dev_user("eve", {"title": "contractor"})  # intentionally no edges
    dev_user("security-lead", {"title": "approver"})  # approves, holds no paths

    group = ag.add_node(db, "group", "security-engineers")
    ps_ro = ag.add_node(db, "permission_set", "prod-readonly")
    ps_ops = ag.add_node(db, "permission_set", "prod-secops")
    role_audit = ag.add_node(db, "role", "prod-security-auditor")
    role_ops = ag.add_node(db, "role", "prod-secops-admin")
    account = ag.add_node(db, "account", "prod")
    ec2 = ag.add_node(db, "asset", "ec2-prod-1")
    secret = ag.add_node(db, "asset", "db-creds-prod")

    ag.add_edge(db, derrick, "member_of", group)
    ag.add_edge(db, marcus, "member_of", group)
    ag.add_edge(db, group, "assigned", ps_ro)
    ag.add_edge(db, group, "assigned", ps_ops)
    ag.add_edge(db, ps_ro, "can_assume", role_audit)
    ag.add_edge(db, ps_ops, "can_assume", role_ops)
    ag.add_edge(db, role_audit, "role_allows", account, {"actions": ["ec2:Describe*"]})
    ag.add_edge(
        db,
        role_ops,
        "role_allows",
        account,
        {
            "actions": [
                "secretsmanager:RotateSecret",
                "iam:DeactivateAccessKey",
                "ticketing:CreateTicket",
            ]
        },
    )
    ag.add_edge(db, account, "account_contains", ec2)
    ag.add_edge(db, account, "account_contains", secret)

    # ---- Object / Ontology Graph ------------------------------------------
    app = og.add_object(db, "application", "payments-api", {"tier": "critical"})
    instance = og.add_object(
        db, "ec2_instance", "ec2-prod-1",
        {"environment": "production", "classification": "internal", "region": "us-east-1"},
    )
    vpc = og.add_object(db, "vpc", "vpc-prod", {"environment": "production"})
    creds = og.add_object(
        db, "secret", "db-creds-prod",
        {"environment": "production", "classification": "sensitive"},
    )
    database = og.add_object(
        db, "database", "payments-db",
        {"environment": "production", "classification": "sensitive"},
    )
    chd = og.add_object(db, "data", "cardholder-data", {"classification": "sensitive"})
    finding = og.add_object(
        db, "finding", "F-2026-0142",
        {"severity": "high", "title": "Suspicious outbound traffic"},
    )
    incident = og.add_object(db, "incident", "INC-42", {"status": "investigating"})
    team = og.add_object(db, "team", "platform-security")

    og.relate(db, app, "runs_on", instance)
    og.relate(db, instance, "in_vpc", vpc)
    og.relate(db, app, "uses", creds)
    og.relate(db, creds, "accesses", database)
    og.relate(db, database, "stores", chd)
    og.relate(db, finding, "affects", instance)
    og.relate(db, incident, "tracks", finding)
    og.relate(db, app, "owned_by", team)

    # ---- Policy: install the default versioned policy document -------------
    policy.active_policy(db)
    db.commit()


def main() -> None:
    from .db import SessionLocal, init_db

    init_db()
    with SessionLocal() as db:
        seed(db)
    print("Database initialized and seeded.")


if __name__ == "__main__":
    main()
