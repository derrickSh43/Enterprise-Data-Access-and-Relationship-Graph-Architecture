"""Run inside the operator-only sandbox container. No cloud mutations."""
import importlib.util
import json
import os
import sys
import traceback
from collections import Counter
from sqlalchemy import select, text
from eda.db import SessionLocal
from eda.models import ConnectorFact, ConnectorState
from eda.connectors.sdk import Connector
from eda import audit

spec = importlib.util.spec_from_file_location("sandbox_sync", "/sandbox/sync.py")
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)


def emit(check, passed, **details):
    print("EDA_RESULT " + json.dumps({"check": check, "status": "PASS" if passed else "FAIL", **details}), flush=True)
    if not passed:
        raise AssertionError(check)


class Observed(Connector):
    def __init__(self, wrapped, tenant):
        self.wrapped, self.tenant, self.expected = wrapped, tenant, {}
        self.kinds = Counter()

    def describe(self):
        return self.wrapped.describe()

    def check_connection(self):
        return self.wrapped.check_connection()

    def snapshot(self):
        for objects, relationships in self.wrapped.snapshot():
            for fact in [*objects, *relationships]:
                self.expected[fact.key(self.tenant)] = fact.model_dump(mode="json")
            for obj in objects:
                self.kinds[obj.ref.kind] += 1
            yield objects, relationships


def live_facts(source_id):
    with SessionLocal() as db:
        facts = db.scalars(select(ConnectorFact).where(ConnectorFact.source_id == source_id,
                                                     ConnectorFact.generation == "live")).all()
        state = db.get(ConnectorState, source_id)
        return {f.fact_key: f.payload for f in facts}, state.sequence


def inspect_source(label, connector, tenant, source_id, provider, namespace):
    observed = Observed(connector, tenant)
    with SessionLocal.begin() as db:
        db.execute(text("SELECT pg_advisory_xact_lock(741002)"))
        count = sync.import_source(db, observed, tenant, source_id, provider, namespace)
    stored, sequence = live_facts(source_id)
    emit(label + "_import_matches_observed_records", stored == observed.expected,
         facts=count, objects=sum(observed.kinds.values()), relationships=count-sum(observed.kinds.values()))
    if label == "aws":
        expected_instance = "aws:" + os.environ["AWS_TEST_INSTANCE_ID"]
        expected_bucket = "aws:arn:aws:s3:::" + os.environ["AWS_TEST_BUCKET"]
        native_ids = {f.get("ref", {}).get("native_id") for f in stored.values()}
        emit("aws_expected_sandbox_resources_present", {expected_instance, expected_bucket} <= native_ids)
    else:
        emit("entra_users_and_groups_observed", observed.kinds["user"] > 0 and observed.kinds["group"] >= 2)

    # Inject a LOCAL failure against the real imported source, in a rolled-back transaction.
    # Never remove memberships or disable identities at the provider.
    class Interrupted(Observed):
        def check_connection(self):
            return {"coverage": "complete"}

        def snapshot(self):
            yield [], []
            raise InterruptedError("deliberate local scan interruption")
    try:
        with SessionLocal.begin() as db:
            db.execute(text("SELECT pg_advisory_xact_lock(741002)"))
            sync.import_source(db, Interrupted(connector, tenant), tenant, source_id, provider, namespace)
    except InterruptedError:
        pass
    after, after_sequence = live_facts(source_id)
    emit(label + "_interrupted_import_preserves_inventory", stored == after and sequence == after_sequence)

    # Recollect to verify subsequent complete scans still commit cleanly.
    repeated = Observed(connector, tenant)
    with SessionLocal.begin() as db:
        db.execute(text("SELECT pg_advisory_xact_lock(741002)"))
        sync.import_source(db, repeated, tenant, source_id, provider, namespace)
    final, _ = live_facts(source_id)
    emit(label + "_repeat_import_matches_latest_observation", final == repeated.expected, facts=len(final))
    with SessionLocal() as db:
        result = audit.verify_chain(db)
    emit(label + "_audit_chain_valid", result.get("ok") is True)


def main(label):
    tenant = os.environ["ENTRA_TENANT_ID"]
    if label == "entra":
        from azure.identity import ClientSecretCredential
        from eda.connectors.entra import EntraConnector
        credential = ClientSecretCredential(tenant, os.environ["ENTRA_COLLECTOR_CLIENT_ID"],
                                            os.environ["ENTRA_COLLECTOR_CLIENT_SECRET"])
        connector = EntraConnector(source_id="entra-sandbox", credential=credential)
        try:
            inspect_source(label, connector, tenant, "entra-sandbox", "entra", "entra:")
        finally:
            connector.client.close()
            credential.close()
    elif label == "aws":
        import boto3
        from eda.connectors.aws import AwsInventoryConnector
        account, region = os.environ["AWS_EXPECTED_ACCOUNT"], os.environ["AWS_REGION"]
        session = boto3.Session(region_name=region)
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        role_name = os.environ["AWS_COLLECTOR_ROLE_ARN"].rsplit("/", 1)[1]
        emit("aws_scoped_role_and_account_match", identity["Account"] == account and
             identity["Arn"].startswith(f"arn:aws:sts::{account}:assumed-role/{role_name}/"))
        source_id = f"aws-{account}-{region}"
        connector = AwsInventoryConnector(source_id=source_id, sts=sts, s3=session.client("s3"),
                    iam=session.client("iam"), ec2=session.client("ec2"))
        inspect_source(label, connector, tenant, source_id, "aws", "aws:")
    elif label == "aws-permissions":
        import boto3
        from botocore.exceptions import ClientError
        session = boto3.Session(region_name=os.environ["AWS_REGION"])
        ec2 = session.client("ec2")
        result = ec2.describe_instances(InstanceIds=[os.environ["AWS_TEST_INSTANCE_ID"]])
        instances = [i for r in result["Reservations"] for i in r["Instances"]]
        emit("aws_target_instance_read_allowed", len(instances) == 1 and instances[0]["InstanceId"] == os.environ["AWS_TEST_INSTANCE_ID"])
        groups = [g["GroupId"] for g in instances[0].get("SecurityGroups", [])]
        result = ec2.describe_security_groups(GroupIds=groups)
        emit("aws_target_security_group_read_allowed", {g["GroupId"] for g in result["SecurityGroups"]} == set(groups))
        try:
            response = session.client("s3").get_object(Bucket=os.environ["AWS_TEST_BUCKET"], Key="samples/fake-record.json")
        except ClientError as exc:
            emit("aws_file_content_read_denied", exc.response["Error"]["Code"] == "AccessDenied")
        else:
            response["Body"].close()
            emit("aws_file_content_read_denied", False)
    else:
        raise ValueError("unknown test source")


if __name__ == "__main__":
    try:
        main(sys.argv[1])
    except Exception:
        traceback.print_exc()
        raise SystemExit(1)
