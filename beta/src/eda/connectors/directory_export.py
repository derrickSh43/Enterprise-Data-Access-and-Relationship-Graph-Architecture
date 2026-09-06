"""Provider-neutral directory export adapter for offline federation fixtures.

The export producer must obtain data from an authoritative provider. This adapter
does not authenticate to an IdP or prove cloud/database grants.
"""
from datetime import datetime
from .sdk import Connector
from .contracts import Manifest, ObjectRecord, Reference, RelationshipRecord


class DirectoryExportConnector(Connector):
    def __init__(self, *, source_id, namespace, users, groups, memberships, observed_at, complete):
        self.source_id, self.namespace = source_id, namespace
        self.users, self.groups, self.memberships = users, groups, memberships
        self.observed_at, self.complete = observed_at, complete

    def describe(self):
        return Manifest(connector_type="directory-export", object_kinds=["user", "group"],
                        relations=["member_of"], capabilities=["snapshot"],
                        permission_semantics="platform_relations",
                        limitations=["Export only; live IdP integration and federation role links remain separate"])

    def check_connection(self):
        return {"coverage": "complete" if self.complete else "partial"}

    def snapshot(self):
        refs = {}
        for kind, rows in (("user", self.users), ("group", self.groups)):
            objects = []
            for row in rows:
                native = self.namespace + row["id"]
                if (kind, row["id"]) in refs:
                    raise ValueError("duplicate directory identity")
                ref = Reference(source_id=self.source_id, native_id=native, kind=kind)
                refs[(kind, row["id"])] = ref
                objects.append(ObjectRecord(ref=ref, display_name=row["name"], observed_at=self.observed_at))
                if len(objects) == 500:
                    yield objects, []
                    objects = []
            if objects:
                yield objects, []
        relations = []
        for user, group in self.memberships:
            relations.append(RelationshipRecord(subject=refs[("user", user)], relation="member_of",
                                                target=refs[("group", group)], observed_at=self.observed_at))
            if len(relations) == 500:
                yield [], relations
                relations = []
        if relations:
            yield [], relations
