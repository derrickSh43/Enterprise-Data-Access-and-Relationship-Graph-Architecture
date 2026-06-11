"""Secure relationship ingestion: collectors feed the access graph.

A collector authenticates with its source-bound credential and may only write
relationships whose node IDs sit inside the source's allowed namespace
(e.g. "okta:"). Validation is all-or-nothing per batch: collector identity,
source enabled, namespace, schema, batch size, relationship types, and kind
consistency are checked before anything touches the graph.

Imported nodes and edges record tenant_id, external_id, source_id, and
observed_at; the existing resolver consumes them unchanged.
"""

import hashlib
import hmac
import secrets as _secrets
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit
from .access_graph import TRAVERSABLE
from .config import settings
from .models import AccessEdge, AccessNode, RelationshipSource

ALLOWED_KINDS = {"user", "group", "role", "permission_set", "service_account", "account", "asset"}
ALLOWED_RELATIONS = set(TRAVERSABLE)


class IngestError(Exception):
    def __init__(self, status: int, detail):
        super().__init__(str(detail))
        self.status = status
        self.detail = detail


def _hash_secret(secret: str) -> str:
    return "secret-sha256:" + hashlib.sha256(secret.encode()).hexdigest()


def register_source(
    db: Session,
    *,
    source_id: str,
    tenant_id: str,
    provider: str,
    allowed_namespace: str,
    secret: str | None = None,
    enabled: bool = True,
) -> tuple[RelationshipSource, str]:
    """Create a collector source. Returns (source, secret) - the secret is
    shown once and only its hash is stored."""
    if db.get(RelationshipSource, source_id) is not None:
        raise IngestError(409, f"source {source_id!r} already exists")
    secret = secret or _secrets.token_urlsafe(32)
    source = RelationshipSource(
        id=source_id,
        tenant_id=tenant_id,
        provider=provider,
        collector_identity=_hash_secret(secret),
        allowed_namespace=allowed_namespace,
        enabled=enabled,
    )
    db.add(source)
    db.flush()
    return source, secret


def authenticate_collector(db: Session, source_id: str, bearer: str) -> RelationshipSource:
    """Fail closed: unknown source, wrong credential, and disabled source all
    return the same 403."""
    source = db.get(RelationshipSource, source_id)
    if (
        source is None
        or not hmac.compare_digest(source.collector_identity, _hash_secret(bearer))
        or not source.enabled
    ):
        raise IngestError(403, "collector not authorized for this source")
    return source


def _validate(source: RelationshipSource, relationships: list[dict], max_batch: int) -> list[str]:
    errors = []
    if len(relationships) == 0:
        errors.append("empty batch")
    if len(relationships) > max_batch:
        errors.append(f"batch of {len(relationships)} exceeds limit {max_batch}")
        return errors
    ns = source.allowed_namespace
    for i, rel in enumerate(relationships):
        where = f"relationships[{i}]"
        for side in ("subject", "target"):
            ref = rel.get(side) or {}
            kind, ext_id = ref.get("kind"), ref.get("id")
            if kind not in ALLOWED_KINDS:
                errors.append(f"{where}.{side}.kind {kind!r} not in {sorted(ALLOWED_KINDS)}")
            if not isinstance(ext_id, str) or not ext_id:
                errors.append(f"{where}.{side}.id missing")
            elif not ext_id.startswith(ns):
                errors.append(
                    f"{where}.{side}.id {ext_id!r} outside source namespace {ns!r}"
                )
        relation = rel.get("relation")
        if relation not in ALLOWED_RELATIONS:
            errors.append(f"{where}.relation {relation!r} not in {sorted(ALLOWED_RELATIONS)}")
        if not isinstance(rel.get("attributes", {}), dict):
            errors.append(f"{where}.attributes must be an object")
    return errors


def _upsert_node(
    db: Session,
    cache: dict,
    *,
    kind: str,
    external_id: str,
    source: RelationshipSource,
    observed_at: datetime,
) -> tuple[AccessNode, bool]:
    if external_id in cache:
        node, created = cache[external_id], False
    else:
        node = db.scalar(
            select(AccessNode).where(
                AccessNode.external_id == external_id, AccessNode.tenant_id == source.tenant_id
            )
        )
        created = node is None
        if created:
            node = AccessNode(
                kind=kind,
                name=external_id,
                attrs={},
                tenant_id=source.tenant_id,
                external_id=external_id,
                source_id=source.id,
                observed_at=observed_at,
            )
            db.add(node)
            db.flush()
        cache[external_id] = node
    if node.kind != kind:
        raise IngestError(
            422, f"{external_id!r} already exists as kind {node.kind!r}, not {kind!r}"
        )
    node.source_id = source.id
    node.observed_at = observed_at
    return node, created


def ingest(
    db: Session,
    *,
    source: RelationshipSource,
    relationships: list[dict],
    observed_at: datetime | None = None,
    max_batch: int | None = None,
) -> dict:
    """Validate then apply a relationship batch atomically. Caller commits."""
    errors = _validate(source, relationships, max_batch or settings.ingest_max_batch)
    if errors:
        raise IngestError(422, errors)

    observed_at = observed_at or datetime.now(timezone.utc)
    cache: dict[str, AccessNode] = {}
    nodes_created = edges_created = edges_updated = 0

    for rel in relationships:
        src, src_new = _upsert_node(
            db, cache,
            kind=rel["subject"]["kind"], external_id=rel["subject"]["id"],
            source=source, observed_at=observed_at,
        )
        dst, dst_new = _upsert_node(
            db, cache,
            kind=rel["target"]["kind"], external_id=rel["target"]["id"],
            source=source, observed_at=observed_at,
        )
        nodes_created += int(src_new) + int(dst_new)

        edge = db.scalar(
            select(AccessEdge).where(
                AccessEdge.src_id == src.id,
                AccessEdge.relation == rel["relation"],
                AccessEdge.dst_id == dst.id,
            )
        )
        if edge is None:
            db.add(
                AccessEdge(
                    src_id=src.id,
                    relation=rel["relation"],
                    dst_id=dst.id,
                    attrs=rel.get("attributes") or {},
                    tenant_id=source.tenant_id,
                    source_id=source.id,
                    observed_at=observed_at,
                )
            )
            edges_created += 1
        else:
            edge.attrs = rel.get("attributes") or {}
            edge.source_id = source.id
            edge.observed_at = observed_at
            edges_updated += 1

    source.last_sync_at = observed_at
    summary = {
        "source_id": source.id,
        "tenant_id": source.tenant_id,
        "relationships": len(relationships),
        "nodes_created": nodes_created,
        "edges_created": edges_created,
        "edges_updated": edges_updated,
        "observed_at": observed_at.isoformat(),
    }
    audit.append(
        db,
        correlation_id=uuid.uuid4().hex,
        subject=f"collector:{source.id}",
        session_id="-",
        event="relationship_ingest",
        action="ingest:relationships",
        target=source.id,
        result="accepted",
        context_summary=summary,
    )
    db.flush()
    return summary
