"""Reference connector for conformance tests and offline onboarding."""
from .sdk import Connector
from .contracts import Manifest


class FixtureConnector(Connector):
    def __init__(self, pages, *, complete=True):
        self.pages = pages
        self.complete = complete

    def describe(self):
        return Manifest(connector_type="fixture", object_kinds=["user", "group", "role", "account", "asset"],
                        relations=["member_of", "assigned", "can_assume", "role_allows", "account_contains"],
                        capabilities=["snapshot", "changes"], permission_semantics="platform_relations")

    def check_connection(self):
        return {"coverage": "complete" if self.complete else "partial"}

    def snapshot(self):
        yield from self.pages
