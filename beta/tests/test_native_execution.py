from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
import json
import pytest
from eda import broker, actions
from eda.native_actions import inspect_instance
from eda.container_runner import command


def test_sts_read_policy_uses_native_supported_scope_and_safe_identity():
    sts = MagicMock()
    sts.assume_role.return_value = {"Credentials": {"Expiration": datetime.now(timezone.utc)+timedelta(seconds=900)}}
    adapter = broker.AwsStsBroker("arn:aws:iam::123456789012:role/inspection", region="us-east-1", sts_client=sts)
    adapter.issue_credentials(subject="entra:arbitrary/user", scope={"actions": ["ec2:DescribeInstances", "ec2:DescribeSecurityGroups"],
        "resources": ["logical-object"]}, ttl_seconds=900, tags={})
    args = sts.assume_role.call_args.kwargs
    policy = json.loads(args["Policy"])
    assert policy["Statement"][0]["Resource"] == "*"
    assert policy["Statement"][0]["Condition"]["StringEquals"]["aws:RequestedRegion"] == "us-east-1"
    assert ":" not in args["RoleSessionName"] and "/" not in args["RoleSessionName"]
    assert args["DurationSeconds"] == 900


def test_real_read_pins_instance_and_declares_every_call():
    client = MagicMock()
    client.describe_instances.return_value = {"Reservations": [{"Instances": [
        {"InstanceId": "i-12345678", "State": {"Name": "running"}, "SecurityGroups": [{"GroupId": "sg-one"}]},
        {"InstanceId": "i-87654321", "State": {"Name": "stopped"}, "Secret": "hidden"}]}]}
    client.describe_security_groups.return_value = {}
    output, calls = inspect_instance({}, "i-12345678", "us-east-1", client=client)
    client.describe_instances.assert_called_once_with(InstanceIds=["i-12345678"])
    client.describe_security_groups.assert_called_once_with(GroupIds=["sg-one"])
    assert "hidden" not in str(output)
    assert {"ec2:" + call["call"] for call in calls} == {
        actions.REGISTRY["inspect_instance"].cloud_action, *actions.REGISTRY["inspect_instance"].additional_cloud_actions}


def test_invalid_native_identifier_never_calls_provider():
    client = MagicMock()
    with pytest.raises(actions.ActionError):
        inspect_instance({}, "caller-chosen-name", "us-east-1", client=client)
    client.describe_instances.assert_not_called()


def test_container_command_confines_offline_job():
    args = command("registry/eda@sha256:" + "a" * 64, "owned-job")
    for flag in ("--read-only", "--cap-drop", "--security-opt", "--pids-limit", "--memory"):
        assert flag in args
    assert args[args.index("--network") + 1] == "none"
    assert "--volume" not in args and "-v" not in args
    with pytest.raises(ValueError):
        command("registry/eda:latest", "job")


def test_revocation_does_not_claim_native_session_revocation(db):
    from test_broker import issue
    report = broker.revoke_grant(issue(db))
    assert report["local_revoked"] is True
    assert report["provider_revoked"] is False
