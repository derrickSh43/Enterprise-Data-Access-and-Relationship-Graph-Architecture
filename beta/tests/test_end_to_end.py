"""End-to-end: the doc's 'Cloud Investigation Request' scenario over HTTP."""


def make_session(client, subject, *, mfa=True, risk_score=0):
    response = client.post(
        "/identity/sessions", json={"subject": subject, "mfa": mfa, "risk_score": risk_score}
    )
    assert response.status_code == 200
    return response.json()["session_token"]


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def submit(client, token, action, resource, **extra):
    response = client.post(
        "/requests",
        json={"action": action, "resource": resource, **extra},
        headers=auth(token),
    )
    assert response.status_code == 200
    return response.json()


def test_investigation_request_full_chain(client):
    token = make_session(client, "derrick")
    trace = submit(
        client, token, "inspect_instance", "ec2-prod-1",
        justification={"case_id": "INC-42"},
    )
    assert trace["outcome"] == "allowed"

    stages = trace["stages"]
    assert stages["identity"]["mfa"] is True
    assert stages["access_path"][0]["src"] == "user:derrick"
    assert stages["policy"]["decision"] == "allowed"
    assert stages["grant"]["credentials"] == "VAULTED"
    assert stages["grant"]["scope"]["read_only"] is True
    assert any(n["name"] == "payments-api" for n in stages["context"]["nodes"])
    assert stages["action_result"]["outputs"]["state"] == "running"

    # full evidence chain retrievable by correlation id (admin capability),
    # chain intact
    admin = make_session(client, "security-lead")
    chain = client.get(
        f"/audit/records/{trace['correlation_id']}", headers=auth(admin)
    ).json()
    assert chain[0]["result"] == "allowed"
    assert chain[0]["policy_version"]
    assert client.get("/audit/verify", headers=auth(admin)).json()["ok"] is True


def test_denials_no_path_no_mfa_no_case(client):
    no_path = submit(
        client, make_session(client, "eve"), "inspect_instance", "ec2-prod-1",
        justification={"case_id": "INC-42"},
    )
    assert no_path["outcome"] == "denied"
    assert no_path["stages"]["access_path"] is None

    no_mfa = submit(
        client, make_session(client, "marcus", mfa=False), "inspect_instance", "ec2-prod-1",
        justification={"case_id": "INC-42"},
    )
    assert no_mfa["outcome"] == "denied"

    no_case = submit(client, make_session(client, "derrick"), "inspect_instance", "ec2-prod-1")
    assert no_case["outcome"] == "denied"
    assert "case" in no_case["error"].lower()


def test_high_risk_action_needs_capable_approval_then_controlled_runner(client):
    requester = make_session(client, "derrick")
    first = submit(
        client, requester, "rotate_secret", "db-creds-prod",
        justification={"case_id": "INC-42"},
    )
    assert first["outcome"] == "approval_required"
    approval = first["stages"]["approval"]
    approval_id = approval["approval_id"]
    # capability is server-derived, never client input
    assert approval["required_capability"] == "approval:rotate_secret"

    # self-approval rejected
    self_attempt = client.post(
        f"/approvals/{approval_id}/decision", json={"approve": True}, headers=auth(requester)
    )
    assert self_attempt.status_code == 400

    # marcus is authenticated and mapped, but holds no approval capability:
    # approval is its own authorization decision, not "anyone but the requester"
    marcus = make_session(client, "marcus")
    incapable = client.post(
        f"/approvals/{approval_id}/decision", json={"approve": True}, headers=auth(marcus)
    )
    assert incapable.status_code == 403
    assert "approval:rotate_secret" in incapable.json()["detail"]

    lead = make_session(client, "security-lead")
    approved = client.post(
        f"/approvals/{approval_id}/decision", json={"approve": True}, headers=auth(lead)
    )
    assert approved.json()["status"] == "approved"
    # the approver's proven access path is preserved as evidence
    assert approved.json()["approver_path"][0]["src"] == "user:security-lead"

    second = submit(
        client, requester, "rotate_secret", "db-creds-prod",
        justification={"case_id": "INC-42"}, approval_id=approval_id,
    )
    assert second["outcome"] == "allowed"
    assert second["stages"]["action_result"]["execution_mode"] == "controlled_runner"

    # replay prevention: the approval was consumed; reusing it does not
    # authorize a third run
    third = submit(
        client, requester, "rotate_secret", "db-creds-prod",
        justification={"case_id": "INC-42"}, approval_id=approval_id,
    )
    assert third["outcome"] == "approval_required"

    assert client.get("/audit/verify", headers=auth(lead)).json()["ok"] is True


def test_feedback_loop_proposes_after_denial_pattern(client):
    eve = make_session(client, "eve")
    for _ in range(3):
        submit(client, eve, "inspect_instance", "ec2-prod-1", justification={"case_id": "INC-42"})

    lead = make_session(client, "security-lead")
    proposals = client.post("/feedback/run", headers=auth(lead)).json()
    assert any(p["kind"] == "repeated_denials" for p in proposals)
    assert all(p["status"] == "proposed" for p in proposals)
