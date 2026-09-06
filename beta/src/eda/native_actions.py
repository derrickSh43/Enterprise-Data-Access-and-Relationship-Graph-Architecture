"""Supported native read action; explicit inputs and minimal returned metadata."""
import re
from .actions import ActionError


def inspect_instance(credentials, instance_id, region, *, client=None):
    if not re.fullmatch(r"i-[0-9a-f]{8,17}", instance_id):
        raise ActionError("invalid native EC2 instance identifier")
    if client is None:
        import boto3
        client = boto3.client("ec2", region_name=region,
            aws_access_key_id=credentials["AccessKeyId"], aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"])
    response = client.describe_instances(InstanceIds=[instance_id])
    found = [instance for reservation in response.get("Reservations", []) for instance in reservation.get("Instances", [])
             if instance.get("InstanceId") == instance_id]
    if len(found) != 1:
        raise ActionError("requested instance unavailable or ambiguous")
    group_ids = sorted({g["GroupId"] for g in found[0].get("SecurityGroups", [])})
    calls = [{"service": "ec2", "call": "DescribeInstances", "request_id": response.get("ResponseMetadata", {}).get("RequestId")}]
    if group_ids:
        groups = client.describe_security_groups(GroupIds=group_ids)
        calls.append({"service": "ec2", "call": "DescribeSecurityGroups", "request_id": groups.get("ResponseMetadata", {}).get("RequestId")})
    return {"instance": instance_id, "state": found[0].get("State", {}).get("Name"),
            "security_groups": group_ids, "mode": "read_only_inspection"}, calls
