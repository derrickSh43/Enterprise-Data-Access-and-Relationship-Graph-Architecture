"""AWS metadata collector using injected boto3 clients; no cloud writes.

Coverage is limited to account S3 bucket metadata, IAM role metadata/trust
documents and EC2 instances in the client's configured region. Effective IAM
evaluation is deliberately unsupported; collected policy documents grant nothing.
"""
from datetime import datetime, timezone
from .sdk import Connector
from .contracts import Manifest, ObjectRecord, Reference


class AwsInventoryConnector(Connector):
    def __init__(self, *, source_id, sts, s3, iam, ec2):
        self.source_id = source_id
        self.sts, self.s3, self.iam, self.ec2 = sts, s3, iam, ec2

    def describe(self):
        return Manifest(connector_type="aws-inventory", object_kinds=["bucket", "role", "ec2_instance"],
                        capabilities=["snapshot"], permission_semantics="inventory_only",
                        limitations=["One account and configured EC2 region per source",
                                     "IAM identity/resource policies, boundaries and SCPs are not evaluated",
                                     "Bucket contents and instance payloads are not collected"])

    def check_connection(self):
        identity = self.sts.get_caller_identity()
        if not identity.get("Account"):
            raise ValueError("AWS account identity unavailable")
        return {"coverage": "complete", "scope": "declared metadata only", "account": identity["Account"]}

    def _object(self, kind, native, name, attributes):
        return ObjectRecord(ref=Reference(source_id=self.source_id, native_id="aws:" + native, kind=kind),
                            display_name=name, observed_at=datetime.now(timezone.utc), attributes=attributes)

    def snapshot(self):
        # Every provider failure propagates; the SDK then cannot complete the snapshot.
        for page in self.s3.get_paginator("list_buckets").paginate():
            objects = [self._object("bucket", "arn:aws:s3:::" + b["Name"], b["Name"], {})
                       for b in page.get("Buckets", [])]
            for offset in range(0, len(objects), 500):
                yield objects[offset:offset+500], []
        for page in self.iam.get_paginator("list_roles").paginate():
            yield [self._object("role", role["Arn"], role["RoleName"],
                                {"trust_policy": role.get("AssumeRolePolicyDocument", {}),
                                 "permission_assessment": "indeterminate"})
                   for role in page.get("Roles", [])], []
        for page in self.ec2.get_paginator("describe_instances").paginate():
            objects = [self._object("ec2_instance", instance["InstanceId"], instance["InstanceId"],
                                    {"state": instance.get("State", {}).get("Name"),
                                     "vpc_id": instance.get("VpcId")})
                       for reservation in page.get("Reservations", []) for instance in reservation.get("Instances", [])]
            for offset in range(0, len(objects), 500):
                yield objects[offset:offset+500], []
