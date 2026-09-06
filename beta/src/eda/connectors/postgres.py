"""PostgreSQL catalog metadata collector. Never selects application rows."""
from datetime import datetime, timezone
from sqlalchemy import text
from .sdk import Connector
from .contracts import Manifest, ObjectRecord, Reference


class PostgresInventoryConnector(Connector):
    def __init__(self, *, source_id, engine, schema):
        if not schema:
            raise ValueError("explicit schema required")
        self.source_id, self.engine, self.schema = source_id, engine, schema

    def describe(self):
        return Manifest(connector_type="postgres-inventory", object_kinds=["table", "column"],
                        capabilities=["snapshot"], permission_semantics="inventory_only",
                        limitations=["One configured schema, metadata visible to collector only",
                                     "RLS, role inheritance, views/functions and effective grants are not evaluated"])

    def check_connection(self):
        with self.engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return {"coverage": "complete", "scope": "collector-visible schema metadata", "schema": self.schema}

    def snapshot(self):
        query = text("SELECT table_name, column_name, data_type FROM information_schema.columns "
                     "WHERE table_schema = :schema ORDER BY table_name, ordinal_position")
        with self.engine.connect() as connection:
            rows = connection.execution_options(stream_results=True).execute(query, {"schema": self.schema}).mappings()
            objects, tables = [], set()
            for row in rows:
                table = row["table_name"]
                now = datetime.now(timezone.utc)
                # JSON tuple encoding avoids collisions from dots inside SQL identifiers.
                import json
                def record(kind, parts, name, attrs):
                    return ObjectRecord(ref=Reference(source_id=self.source_id, kind=kind,
                            native_id="pg:" + json.dumps(parts, separators=(",", ":"))),
                            display_name=name, observed_at=now, attributes=attrs)
                if table not in tables:
                    tables.add(table)
                    objects.append(record("table", [self.schema, table], table, {"schema": self.schema}))
                objects.append(record("column", [self.schema, table, row["column_name"]], row["column_name"],
                                      {"table": table, "data_type": row["data_type"]}))
                if len(objects) >= 500:
                    yield objects, []
                    objects = []
            if objects:
                yield objects, []
