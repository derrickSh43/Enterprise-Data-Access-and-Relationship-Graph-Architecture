from eda import policy


def make_input(**overrides):
    base = {
        "subject": "derrick",
        "session": {"mfa": True, "risk_score": 10},
        "action": {"name": "inspect_instance", "cloud_action": "ec2:DescribeInstances",
                   "read_only": True, "risk": "low"},
        "resource": {"name": "ec2-prod-1", "environment": "production",
                     "classification": "internal"},
        "access_path_exists": True,
        "justification": {"case_id": "INC-42"},
        "approval_present": False,
    }
    base.update(overrides)
    return base


def test_read_only_with_mfa_and_case_is_allowed(db):
    decision = policy.evaluate(db, make_input())
    assert decision.decision == "allowed"
    assert {"type": "read_only"} in decision.obligations
    assert decision.policy_version


def test_no_access_path_denies(db):
    assert policy.evaluate(db, make_input(access_path_exists=False)).decision == "denied"


def test_missing_mfa_denies(db):
    decision = policy.evaluate(db, make_input(session={"mfa": False, "risk_score": 0}))
    assert decision.decision == "denied"
    assert "MFA" in decision.reason


def test_high_risk_session_denies(db):
    decision = policy.evaluate(db, make_input(session={"mfa": True, "risk_score": 85}))
    assert decision.decision == "denied"


def test_production_without_case_id_denies(db):
    assert policy.evaluate(db, make_input(justification={})).decision == "denied"


def test_write_requires_approval(db):
    decision = policy.evaluate(
        db,
        make_input(
            action={"name": "rotate_secret", "cloud_action": "secretsmanager:RotateSecret",
                    "read_only": False, "risk": "high"}
        ),
    )
    assert decision.decision == "approval_required"


def test_approved_write_is_allowed_via_controlled_runner(db):
    decision = policy.evaluate(
        db,
        make_input(
            action={"name": "rotate_secret", "cloud_action": "secretsmanager:RotateSecret",
                    "read_only": False, "risk": "high"},
            approval_present=True,
        ),
    )
    assert decision.decision == "allowed"
    assert {"type": "controlled_runner"} in decision.obligations


def test_deny_wins_over_allow_and_approval(db):
    decision = policy.evaluate(
        db,
        make_input(session={"mfa": False, "risk_score": 0}, approval_present=True),
    )
    assert decision.decision == "denied"
