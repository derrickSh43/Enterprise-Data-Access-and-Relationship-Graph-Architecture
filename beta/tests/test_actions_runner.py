"""Action/resource compatibility, typed input validation, controlled runner."""

import pytest

from eda import actions, runner


def make_session(client, subject, **kw):
    return client.post("/identity/sessions", json={"subject": subject, **kw}).json()[
        "session_token"
    ]


def auth(token):
    return {"Authorization": f"Bearer {token}"}


# --- Item 2: action/resource compatibility -----------------------------------
def test_action_rejected_for_incompatible_resource_kind(client):
    token = make_session(client, "derrick")
    trace = client.post(
        "/requests",
        json={"action": "inspect_instance", "resource": "db-creds-prod",
              "justification": {"case_id": "INC-42"}},
        headers=auth(token),
    ).json()
    assert trace["outcome"] == "denied"
    assert "does not apply to resource kind 'secret'" in trace["error"]


def test_kind_restricted_action_rejected_for_unmodeled_resource():
    action = actions.get_action("inspect_instance")
    with pytest.raises(actions.ActionError, match="not modeled"):
        actions.check_compatibility(action, None)
    actions.check_compatibility(actions.get_action("view_asset"), None)  # "*" is fine


# --- Item 9: typed input validation ------------------------------------------
def test_unknown_fields_rejected(client):
    token = make_session(client, "derrick")
    trace = client.post(
        "/requests",
        json={"action": "inspect_instance", "resource": "ec2-prod-1",
              "inputs": {"surprise": "field"},
              "justification": {"case_id": "INC-42"}},
        headers=auth(token),
    ).json()
    assert trace["outcome"] == "denied"
    assert "invalid inputs" in trace["error"]


def test_length_limits_enforced():
    action = actions.get_action("open_ticket")
    with pytest.raises(actions.ActionError, match="invalid inputs"):
        actions.validate_inputs(action, {"summary": "x"})  # below min_length
    with pytest.raises(actions.ActionError, match="invalid inputs"):
        actions.validate_inputs(action, {"summary": "x" * 501})  # above max_length
    with pytest.raises(actions.ActionError, match="invalid inputs"):
        actions.validate_inputs(action, {})  # required key missing
    assert actions.validate_inputs(action, {"summary": "valid summary"}) == {
        "summary": "valid summary"
    }


def test_wrong_types_rejected():
    action = actions.get_action("open_ticket")
    with pytest.raises(actions.ActionError, match="invalid inputs"):
        actions.validate_inputs(action, {"summary": {"not": "a string"}})


# --- Item 8: controlled runner is a real boundary ------------------------------
def test_runner_enforces_timeout():
    with pytest.raises(runner.RunnerTimeout):
        runner.run_controlled(
            "eda.runner._selftest_sleep",
            credentials={"AccessKeyId": "X"},
            resource="r",
            inputs={"seconds": 30},
            allowed_outputs=("slept",),
            timeout_seconds=1,
        )


def test_runner_returns_only_approved_outputs():
    outputs, api_calls = runner.run_controlled(
        "eda.runner._selftest_leaky",
        credentials={"AccessKeyId": "AKIA-SECRET", "SecretAccessKey": "shhh"},
        resource="r",
        inputs={},
        allowed_outputs=("approved_key",),
    )
    assert outputs == {"approved_key": "fine"}
    assert "stolen_credentials" not in outputs  # exfiltration attempt stripped


def test_runner_surfaces_handler_failures():
    with pytest.raises(runner.RunnerError, match="ModuleNotFoundError|AttributeError"):
        runner.run_controlled(
            "eda.runner._no_such_handler",
            credentials={},
            resource="r",
            inputs={},
            allowed_outputs=(),
            timeout_seconds=10,
        )
