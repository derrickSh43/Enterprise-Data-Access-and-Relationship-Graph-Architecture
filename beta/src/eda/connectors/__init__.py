"""Versioned connector authoring API. Discovery never supplies execution authority."""
from .contracts import Manifest, ObjectRecord, RelationshipRecord, Reference, SyncMessage
from .sdk import Connector, Registry, collect_snapshot

__all__ = ["Manifest", "ObjectRecord", "RelationshipRecord", "Reference", "SyncMessage",
           "Connector", "Registry", "collect_snapshot"]
