from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy import select
from eda import actions, execution
from eda.db import SessionLocal
from eda.models import Execution
from test_end_to_end import make_session, auth


def approved_request(client):
    token = make_session(client, "derrick")
    body = {"action": "rotate_secret", "resource": "db-creds-prod", "justification": {"case_id": "INC-42"}}
    pending = client.post("/requests", json=body, headers=auth(token)).json()
    approval = pending["stages"]["approval"]["approval_id"]
    lead = make_session(client, "security-lead")
    assert client.post(f"/approvals/{approval}/decision", json={"approve": True}, headers=auth(lead)).status_code == 200
    return token, {**body, "approval_id": approval}


def test_retry_does_not_repeat_effect_and_intent_precedes_action(client, monkeypatch):
    token, body = approved_request(client)
    calls = []
    def run(db, **kwargs):
        with SessionLocal() as separate:
            assert separate.scalar(select(Execution)).state == "running"
        calls.append(1)
        return {"outputs": {}, "api_calls": []}
    monkeypatch.setattr(actions, "execute", run)
    headers = {**auth(token), "Idempotency-Key": "logical-operation"}
    assert client.post("/requests", json=body, headers=headers).json()["outcome"] == "allowed"
    replay = client.post("/requests", json=body, headers=headers).json()
    assert replay["stages"]["execution"]["replayed"]
    assert len(calls) == 1
    conflict = {**body, "justification": {"case_id": "different"}}
    assert client.post("/requests", json=conflict, headers=headers).json()["outcome"] == "denied"


def test_uncertain_effect_is_not_automatically_retried(client, monkeypatch):
    token, body = approved_request(client)
    def fail(db, **kwargs):
        raise actions.ActionError("provider response lost")
    monkeypatch.setattr(actions, "execute", fail)
    headers = {**auth(token), "Idempotency-Key": "uncertain"}
    assert client.post("/requests", json=body, headers=headers).json()["outcome"] == "error"
    replay = client.post("/requests", json=body, headers=headers).json()
    assert replay["outcome"] == "outcome_unknown"


def test_changed_justification_cannot_spend_approval(client):
    token, body = approved_request(client)
    body["justification"] = {"case_id": "UNAPPROVED"}
    assert client.post("/requests", json=body, headers=auth(token)).json()["outcome"] == "approval_required"


def test_crash_after_effect_preserves_running_intent_for_recovery(client, monkeypatch):
    token, body = approved_request(client)
    effects = []
    def crash(db, **kwargs):
        effects.append("effect")
        raise RuntimeError("process lost after provider success")
    monkeypatch.setattr(actions, "execute", crash)
    headers = {**auth(token), "Idempotency-Key": "crash-operation"}
    with pytest.raises(RuntimeError):
        client.post("/requests", json=body, headers=headers)
    replay = client.post("/requests", json=body, headers=headers).json()
    assert replay["outcome"] == "running"
    assert effects == ["effect"]
    with SessionLocal() as db:
        execution.mark_interrupted(db, before=datetime.now(timezone.utc)+timedelta(seconds=1))
        db.commit()
    assert client.post("/requests", json=body, headers=headers).json()["outcome"] == "outcome_unknown"
    assert effects == ["effect"]
