import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def _uuid() -> str:
    return uuid.uuid4().hex


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------
# 1. Access Graph: who can reach what (authority relationships)
# --------------------------------------------------------------------------
class AccessNode(Base):
    """A principal or resource in the authority graph.

    kinds: user, group, role, permission_set, service_account, account, asset

    Provenance: imported nodes carry the tenant they belong to, the canonical
    external ID they map to (e.g. "okta:00u123"), the relationship source that
    asserted them, and when they were last observed. Seeded nodes (tests/local
    demos) leave these null.
    """

    __tablename__ = "access_nodes"
    __table_args__ = (UniqueConstraint("kind", "name"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    kind: Mapped[str] = mapped_column(String(40), index=True)
    name: Mapped[str] = mapped_column(String(300), index=True)
    attrs: Mapped[dict] = mapped_column(JSON, default=dict)
    tenant_id: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    external_id: Mapped[str | None] = mapped_column(String(300), nullable=True, index=True)
    source_id: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AccessEdge(Base):
    """Directed authority relationship.

    relations: member_of, assigned, can_assume, role_allows, account_contains, ...
    For role_allows edges, attrs["actions"] lists allowed cloud actions
    (wildcards supported, e.g. "ec2:Describe*").
    """

    __tablename__ = "access_edges"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    src_id: Mapped[str] = mapped_column(String(32), index=True)
    relation: Mapped[str] = mapped_column(String(60), index=True)
    dst_id: Mapped[str] = mapped_column(String(32), index=True)
    attrs: Mapped[dict] = mapped_column(JSON, default=dict)
    tenant_id: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    source_id: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RelationshipSource(Base):
    """A registered collector feed (e.g. okta-directory-prod, prisma-ciem-prod).

    `collector_identity` binds the source to exactly one credential
    ("secret-sha256:<hex>" of the collector's bearer secret, or
    "oidc:<issuer>|<subject>" for a workload identity). `allowed_namespace`
    confines every node ID the collector may write (e.g. "okta:"), so a
    collector can never assert relationships for another tenant or source.
    """

    __tablename__ = "relationship_sources"

    id: Mapped[str] = mapped_column(String(120), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(120), index=True)
    provider: Mapped[str] = mapped_column(String(60))
    collector_identity: Mapped[str] = mapped_column(String(300))
    allowed_namespace: Mapped[str] = mapped_column(String(120))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# --------------------------------------------------------------------------
# 4. Object / Ontology Graph: what things are and how they connect
# --------------------------------------------------------------------------
class ObjectNode(Base):
    """Operational object: application, asset, secret, database, incident, team, ..."""

    __tablename__ = "object_nodes"
    __table_args__ = (UniqueConstraint("kind", "name"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    kind: Mapped[str] = mapped_column(String(40), index=True)
    name: Mapped[str] = mapped_column(String(200), index=True)
    # attrs may include: environment, classification (public|internal|sensitive),
    # owner, restricted_fields (attr keys redacted for non-root views)
    attrs: Mapped[dict] = mapped_column(JSON, default=dict)
    tenant_id: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)


class ObjectEdge(Base):
    """Ontology relationship: runs_on, contains, uses, stores, affects, owned_by, ..."""

    __tablename__ = "object_edges"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    src_id: Mapped[str] = mapped_column(String(32), index=True)
    relation: Mapped[str] = mapped_column(String(60), index=True)
    dst_id: Mapped[str] = mapped_column(String(32), index=True)
    attrs: Mapped[dict] = mapped_column(JSON, default=dict)


# --------------------------------------------------------------------------
# 2. Policy Engine: versioned policy documents
# --------------------------------------------------------------------------
class PolicyRecord(Base):
    """Versioned policy document with a controlled lifecycle.

    status: draft -> active -> retired. Activation happens only through the
    policy service (validated, audited); `checksum` covers the document so a
    direct database edit of an active policy fails closed at evaluation time.
    """

    __tablename__ = "policy_records"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    version: Mapped[str] = mapped_column(String(60), unique=True)
    document: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(20), default="draft", index=True)
    checksum: Mapped[str] = mapped_column(String(64))
    created_by: Mapped[str] = mapped_column(String(200), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# --------------------------------------------------------------------------
# 3. Authority Broker: temporary scoped grants
# --------------------------------------------------------------------------
class Grant(Base):
    __tablename__ = "grants"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    subject: Mapped[str] = mapped_column(String(200), index=True)
    scope: Mapped[dict] = mapped_column(JSON)  # {actions, resources, read_only}
    session_tags: Mapped[dict] = mapped_column(JSON, default=dict)
    broker_kind: Mapped[str] = mapped_column(String(40))  # mock_sts | aws_sts | ...
    # Opaque vault reference. Usable credential material is never persisted in
    # the control-plane database; it lives in the broker's credential vault
    # and is released only to the executor (or confined to the controlled
    # runner) for the grant's lifetime.
    credential_ref: Mapped[str] = mapped_column(String(64))
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    correlation_id: Mapped[str] = mapped_column(String(32), index=True)
    tenant_id: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)


# --------------------------------------------------------------------------
# Approvals (used by Policy Engine require_approval decisions)
# --------------------------------------------------------------------------
class Approval(Base):
    """A pending/decided approval, bound to one exact request.

    `required_capability` is server-derived ("approval:<action>") - clients
    never supply it. Approving requires a proven access path showing the
    approver holds that capability for the target resource; the path is
    preserved as `approver_path` evidence. Approvals expire, and are consumed
    atomically exactly once (status: pending -> approved -> consumed).
    """

    __tablename__ = "approvals"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    subject: Mapped[str] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(100))
    resource: Mapped[str] = mapped_column(String(200))
    inputs_hash: Mapped[str] = mapped_column(String(64), default="")
    required_capability: Mapped[str] = mapped_column(String(120))
    justification: Mapped[dict] = mapped_column(JSON, default=dict)
    # pending | approved | rejected | consumed
    status: Mapped[str] = mapped_column(String(20), default="pending")
    approver: Mapped[str | None] = mapped_column(String(200), nullable=True)
    approver_path: Mapped[list | None] = mapped_column(JSON, nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    correlation_id: Mapped[str] = mapped_column(String(32), index=True)
    tenant_id: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)


# --------------------------------------------------------------------------
# 6. Audit / Evidence Layer: append-only, hash-chained
# --------------------------------------------------------------------------
class AuditRecord(Base):
    __tablename__ = "audit_records"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    id: Mapped[str] = mapped_column(String(32), unique=True, default=_uuid)
    correlation_id: Mapped[str] = mapped_column(String(32), index=True)
    tenant_id: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    subject: Mapped[str] = mapped_column(String(200), index=True)
    session_id: Mapped[str] = mapped_column(String(64))
    event: Mapped[str] = mapped_column(String(60), index=True)  # request|approval|policy_change|...
    action: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    target: Mapped[str | None] = mapped_column(String(200), nullable=True)
    access_path: Mapped[list | None] = mapped_column(JSON, nullable=True)
    policy_input: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    policy_decision: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    policy_version: Mapped[str | None] = mapped_column(String(60), nullable=True)
    approval: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    grant: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # credential-redacted
    api_calls: Mapped[list | None] = mapped_column(JSON, nullable=True)
    context_summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    result: Mapped[str] = mapped_column(String(40))  # allowed|denied|approval_required|error|...
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # unique: a database-level backstop against forked chain heads - two
    # concurrent appends can never share the same predecessor.
    prev_hash: Mapped[str] = mapped_column(String(64), unique=True)
    hash: Mapped[str] = mapped_column(String(64), unique=True)


# --------------------------------------------------------------------------
# 7. Local AI Feedback Loop: recommendations, human-gated
# --------------------------------------------------------------------------
class Recommendation(Base):
    __tablename__ = "recommendations"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    kind: Mapped[str] = mapped_column(String(60), index=True)
    summary: Mapped[str] = mapped_column(Text)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="proposed")  # proposed|approved|rejected
    decided_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    tenant_id: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)


class IngestReceipt(Base):
    """Idempotency record for collector batches: replaying the same
    Idempotency-Key returns the original summary without reapplying."""

    __tablename__ = "ingest_receipts"
    __table_args__ = (UniqueConstraint("source_id", "idempotency_key"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    source_id: Mapped[str] = mapped_column(String(120), index=True)
    idempotency_key: Mapped[str] = mapped_column(String(200))
    summary: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
