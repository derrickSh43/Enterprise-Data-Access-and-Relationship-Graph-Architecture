"""Language-neutral v1 envelopes. Generated JSON schemas live in contracts/."""
import hashlib
import json
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, AwareDatetime, model_validator


class Envelope(BaseModel):
    model_config = ConfigDict(extra="forbid")


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class Reference(Envelope):
    source_id: str = Field(min_length=1, max_length=120)
    native_id: str = Field(min_length=1, max_length=300)
    kind: str = Field(min_length=1, max_length=60)

    def canonical_id(self, tenant: str) -> str:
        return "eda:" + digest([tenant, self.source_id, self.kind, self.native_id])


class ObjectRecord(Envelope):
    ref: Reference
    display_name: str = Field(min_length=1, max_length=300)
    observed_at: AwareDatetime
    attributes: dict = Field(default_factory=dict)

    def key(self, tenant: str) -> str:
        return self.ref.canonical_id(tenant)


class RelationshipRecord(Envelope):
    subject: Reference
    relation: str = Field(min_length=1, max_length=60)
    target: Reference
    observed_at: AwareDatetime
    attributes: dict = Field(default_factory=dict)

    def key(self, tenant: str) -> str:
        return "rel:" + digest([self.subject.canonical_id(tenant), self.relation,
                                self.target.canonical_id(tenant)])


class Manifest(Envelope):
    protocol_version: Literal["1"] = "1"
    connector_type: str = Field(min_length=1, max_length=120)
    object_kinds: list[str] = Field(min_length=1, max_length=100)
    relations: list[str] = Field(default_factory=list, max_length=100)
    capabilities: list[Literal["snapshot", "changes", "context", "permissions"]]
    # Foreign references are administrator-approved rules, not connector claims.
    foreign_references: dict[str, list[str]] = Field(default_factory=dict)
    permission_semantics: Literal["inventory_only", "platform_relations"] = "inventory_only"
    limitations: list[str] = Field(default_factory=list)


class SyncMessage(Envelope):
    protocol_version: Literal["1"] = "1"
    sequence: int = Field(ge=1)
    operation: Literal["begin", "page", "complete", "abort", "delta"]
    snapshot_id: str | None = Field(default=None, max_length=120)
    objects: list[ObjectRecord] = Field(default_factory=list, max_length=1000)
    relationships: list[RelationshipRecord] = Field(default_factory=list, max_length=1000)
    tombstones: list[str] = Field(default_factory=list, max_length=1000)
    coverage: Literal["complete", "partial"] = "partial"

    @model_validator(mode="after")
    def shape(self):
        if self.operation != "delta" and not self.snapshot_id:
            raise ValueError("snapshot_id required for snapshot operations")
        if self.operation == "delta" and self.snapshot_id:
            raise ValueError("delta cannot belong to a snapshot")
        if self.operation in {"begin", "complete", "abort"} and (self.objects or self.relationships or self.tombstones):
            raise ValueError("control messages cannot contain facts")
        if self.operation != "delta" and self.tombstones:
            raise ValueError("only delta accepts tombstones")
        return self
