"""Approval authorization (capability-based) and replay prevention."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update

from eda.models import Approval


def make_session(client, subject, **kw):
    return client.post("/identity/sessions", json={"subject": subject, **kw}).json()[
        "session_token"
    ]


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def request_rotation(client, token, **extra):
    return client.post(
        "/requests",
        json={"action": "rotate_secret", "resource": "db-creds-prod",
              "justification": {"case_id": "INC-42"}, **extra},
        headers=auth(token),
    ).json()


def test_required_capability_is_server_derived(client):
    trace = request_rotation(client, make_session(client, "derrick"))
    assert trace["stages"]["approval"]["required_capability"] == "approval:rotate_secret"

    from eda.db import SessionLocal

    with SessionLocal() as db:
        record = db.get(Approval, trace["stages"]["approval"]["approval_id"])
        assert record.required_capability == "approval:rotate_secret"
        assert record.expires_at is not None


def test_expired_approval_request_cannot_be_decided(client):
    trace = request_rotation(client, make_session(client, "derrick"))
    approval_id = trace["stages"]["approval"]["approval_id"]

    from eda.db import SessionLocal

    with SessionLocal() as db:
        db.execute(
            update(Approval)
            .where(Approval.id == approval_id)
            .values(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
        )
        db.commit()

    lead = make_session(client, "security-lead")
    response = client.post(
        f"/approvals/{approval_id}/decision", json={"approve": True}, headers=auth(lead)
    )
    assert response.status_code == 400
    assert "expired" in response.json()["detail"]


def test_expired_approval_is_not_honored_at_use(client):
    requester = make_session(client, "derrick")
    trace = request_rotation(client, requester)
    approval_id = trace["stages"]["approval"]["approval_id"]
    lead = make_session(client, "security-lead")
    client.post(f"/approvals/{approval_id}/decision", json={"approve": True}, headers=auth(lead))

    from eda.db import SessionLocal

    with SessionLocal() as db:
        db.execute(
            update(Approval)
            .where(Approval.id == approval_id)
            .values(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
        )
        db.commit()

    retry = request_rotation(client, requester, approval_id=approval_id)
    assert retry["outcome"] == "approval_required"  # expired approval ignored


def test_approval_bound_to_exact_inputs(client):
    requester = make_session(client, "derrick")
    first = client.post(
        "/requests",
        json={"action": "open_ticket", "resource": "ec2-prod-1",
              "inputs": {"summary": "Investigate finding F-2026-0142"},
              "justification": {"case_id": "INC-42"}},
        headers=auth(requester),
    ).json()
    assert first["outcome"] == "approval_required"
    approval_id = first["stages"]["approval"]["approval_id"]

    lead = make_session(client, "security-lead")
    client.post(f"/approvals/{approval_id}/decision", json={"approve": True}, headers=auth(lead))

    # different inputs, same approval id: not the request that was approved
    swapped = client.post(
        "/requests",
        json={"action": "open_ticket", "resource": "ec2-prod-1",
              "inputs": {"summary": "Something else entirely"},
              "justification": {"case_id": "INC-42"}, "approval_id": approval_id},
        headers=auth(requester),
    ).json()
    assert swapped["outcome"] == "approval_required"

    # the exact approved request goes through
    exact = client.post(
        "/requests",
        json={"action": "open_ticket", "resource": "ec2-prod-1",
              "inputs": {"summary": "Investigate finding F-2026-0142"},
              "justification": {"case_id": "INC-42"}, "approval_id": approval_id},
        headers=auth(requester),
    ).json()
    assert exact["outcome"] == "allowed"


def test_consumption_is_atomic_compare_and_swap(db):
    """Two transactions racing to consume one approval: exactly one wins."""
    approval = Approval(
        subject="derrick", action="rotate_secret", resource="db-creds-prod",
        inputs_hash="x", required_capability="approval:rotate_secret",
        status="approved", expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        correlation_id="c1", tenant_id="local",
    )
    db.add(approval)
    db.commit()

    def try_consume():
        result = db.execute(
            update(Approval)
            .where(Approval.id == approval.id, Approval.status == "approved")
            .values(status="consumed", consumed_at=datetime.now(timezone.utc))
        )
        return result.rowcount

    assert try_consume() == 1
    assert try_consume() == 0  # the compare-and-swap admits exactly one winner


def test_rejected_approval_not_usable(client):
    requester = make_session(client, "derrick")
    trace = request_rotation(client, requester)
    approval_id = trace["stages"]["approval"]["approval_id"]
    lead = make_session(client, "security-lead")
    rejected = client.post(
        f"/approvals/{approval_id}/decision", json={"approve": False}, headers=auth(lead)
    )
    assert rejected.json()["status"] == "rejected"
    retry = request_rotation(client, requester, approval_id=approval_id)
    assert retry["outcome"] == "approval_required"


def test_approval_capability_does_not_confer_execution(client):
    """Separation of duties: security-lead can approve rotations but holds no
    execution path - their own rotation request is denied for lack of one."""
    lead = make_session(client, "security-lead")
    trace = request_rotation(client, lead)
    assert trace["outcome"] == "denied"
    assert trace["stages"]["access_path"] is None
