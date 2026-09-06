"""Operator-run sandbox inventory import. Not an agent or autonomous executor.

Uses direct local DB access to bootstrap sources without weakening HTTP auth.
One transaction per source means failed scans leave the previous inventory intact.
"""
import os
from sqlalchemy import select, func, text
from eda.db import SessionLocal
from eda.models import RelationshipSource, ConnectorState, ConnectorFact
from eda.ingestion import register_source
from eda.connectors.sync import register, apply_message
from eda.connectors.sdk import collect_snapshot
from eda.connectors.contracts import SyncMessage


def import_source(db, connector, tenant, source_id, provider, namespace):
    source = db.get(RelationshipSource, source_id)
    if source is None:
        source, _ = register_source(db, source_id=source_id, tenant_id=tenant,
                                    provider=provider, allowed_namespace=namespace)
        # This operator tool owns local source delivery; no HTTP token is exposed.
        register(db, source, connector.describe())
    if (source.tenant_id, source.provider, source.allowed_namespace, source.enabled) != (
            tenant, provider, namespace, True):
        raise ValueError("Existing source configuration differs; operator review required")
    state = db.get(ConnectorState, source_id)
    if state is None or state.manifest != connector.describe().model_dump(mode="json"):
        raise ValueError("Manifest differs; operator review required")
    if state.snapshot_id:
        apply_message(db, source, SyncMessage(sequence=state.sequence + 1,
                      operation="abort", snapshot_id=state.snapshot_id))
    for message in collect_snapshot(connector, first_sequence=state.sequence + 1):
        apply_message(db, source, message)
    return db.scalar(select(func.count()).select_from(ConnectorFact).where(
        ConnectorFact.source_id == source_id, ConnectorFact.generation == "live"))


def run():
    import boto3
    from azure.identity import ClientSecretCredential
    from eda.connectors.entra import EntraConnector
    from eda.connectors.aws import AwsInventoryConnector
    required = ["ENTRA_TENANT_ID", "ENTRA_COLLECTOR_CLIENT_ID", "ENTRA_COLLECTOR_CLIENT_SECRET",
                "AWS_REGION", "AWS_EXPECTED_ACCOUNT", "AWS_COLLECTOR_ROLE_ARN",
                "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]
    if any(not os.environ.get(key) for key in required):
        raise ValueError("Missing connector settings or temporary AWS session credentials")
    region, account = os.environ["AWS_REGION"], os.environ["AWS_EXPECTED_ACCOUNT"]
    tenant = os.environ["ENTRA_TENANT_ID"]
    credential = ClientSecretCredential(tenant, os.environ["ENTRA_COLLECTOR_CLIENT_ID"],
                                        os.environ["ENTRA_COLLECTOR_CLIENT_SECRET"])
    entra = EntraConnector(source_id="entra-sandbox", credential=credential)
    try:
        with SessionLocal.begin() as db:
            # Serialize operator runs against this database, including registrations.
            db.execute(text("SELECT pg_advisory_xact_lock(741002)"))
            count = import_source(db, entra, tenant, "entra-sandbox", "entra", "entra:")
        print(f"Entra: committed {count} inventory facts", flush=True)
    finally:
        entra.client.close()
        credential.close()
    role = os.environ["AWS_COLLECTOR_ROLE_ARN"]
    if not role.startswith(f"arn:aws:iam::{account}:role/"):
        raise ValueError("Collector role belongs to a different account")
    temporary = boto3.client("sts", region_name=region).assume_role(
        RoleArn=role, RoleSessionName="eda-sandbox-inventory", DurationSeconds=900)["Credentials"]
    session = boto3.Session(region_name=region, aws_access_key_id=temporary["AccessKeyId"],
                            aws_secret_access_key=temporary["SecretAccessKey"],
                            aws_session_token=temporary["SessionToken"])
    sts = session.client("sts")
    if sts.get_caller_identity()["Account"] != account:
        raise ValueError("Unexpected AWS account")
    connector = AwsInventoryConnector(source_id=f"aws-{account}-{region}", sts=sts,
        s3=session.client("s3"), iam=session.client("iam"), ec2=session.client("ec2"))
    with SessionLocal.begin() as db:
        db.execute(text("SELECT pg_advisory_xact_lock(741002)"))
        count = import_source(db, connector, tenant, f"aws-{account}-{region}", "aws", "aws:")
    print(f"AWS: committed {count} inventory facts; native permissions remain indeterminate", flush=True)


if __name__ == "__main__":
    try:
        run()
    except Exception as exc:
        # Provider exception bodies can contain credentials or private directory data.
        print(f"Sandbox import failed ({type(exc).__name__}); check configuration, consent and session expiry.", flush=True)
        raise SystemExit(1) from None
