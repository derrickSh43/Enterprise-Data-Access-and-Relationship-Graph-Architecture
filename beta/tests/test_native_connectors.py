from datetime import datetime, timezone
from unittest.mock import MagicMock
import pytest
from eda.connectors.aws import AwsInventoryConnector
from eda.connectors.postgres import PostgresInventoryConnector
from eda.connectors.directory_export import DirectoryExportConnector
from eda.connectors.sdk import collect_snapshot


def test_aws_paginates_metadata_and_declares_no_authority():
    sts, s3, iam, ec2 = (MagicMock() for _ in range(4))
    sts.get_caller_identity.return_value = {"Account": "123"}
    s3.get_paginator.return_value.paginate.return_value = [{"Buckets": [{"Name": "one"}]}, {"Buckets": [{"Name": "two"}]}]
    iam.get_paginator.return_value.paginate.return_value = [{"Roles": [{"Arn": "arn:aws:iam::123:role/r", "RoleName": "r"}]}]
    ec2.get_paginator.return_value.paginate.return_value = [{"Reservations": [{"Instances": [{"InstanceId": "i-1"}]}]}]
    connector = AwsInventoryConnector(source_id="aws", sts=sts, s3=s3, iam=iam, ec2=ec2)
    messages = list(collect_snapshot(connector))
    assert sum(len(m.objects) for m in messages) == 4
    assert messages[-1].operation == "complete"
    assert connector.describe().permission_semantics == "inventory_only"
    s3.get_object.assert_not_called()


def test_aws_provider_failure_cannot_complete_snapshot():
    sts, s3, iam, ec2 = (MagicMock() for _ in range(4))
    sts.get_caller_identity.return_value = {"Account": "123"}
    s3.get_paginator.side_effect = RuntimeError("denied")
    stream = collect_snapshot(AwsInventoryConnector(source_id="aws", sts=sts, s3=s3, iam=iam, ec2=ec2))
    assert next(stream).operation == "begin"
    with pytest.raises(RuntimeError):
        next(stream)


def test_postgres_uses_bound_schema_and_no_application_data():
    engine = MagicMock()
    connection = engine.connect.return_value.__enter__.return_value
    query_connection = connection.execution_options.return_value
    query_connection.execute.return_value.mappings.return_value = [
        {"table_name": "payments", "column_name": "amount", "data_type": "numeric"}]
    connector = PostgresInventoryConnector(source_id="pg", engine=engine, schema="public'; DROP TABLE x;--")
    messages = list(collect_snapshot(connector))
    query, parameters = query_connection.execute.call_args.args
    assert ":schema" in str(query)
    assert "DROP TABLE" not in str(query)
    assert parameters["schema"] == connector.schema
    assert sum(len(m.objects) for m in messages) == 2


def test_directory_export_links_stable_ids_not_display_names():
    connector = DirectoryExportConnector(source_id="idp", namespace="idp:",
        users=[{"id": "u1", "name": "Same"}, {"id": "u2", "name": "Same"}],
        groups=[{"id": "g", "name": "Team"}], memberships=[("u1", "g")],
        observed_at=datetime.now(timezone.utc), complete=True)
    messages = list(collect_snapshot(connector))
    relations = [r for m in messages for r in m.relationships]
    assert len(relations) == 1
    assert relations[0].subject.native_id == "idp:u1"
