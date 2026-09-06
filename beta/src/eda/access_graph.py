"""Access Graph: discovers and proves authority paths.

It answers "what access paths exist?" - it does NOT make the final
authorization decision (that is the Policy Engine's job).

Reference implementation uses an in-Python BFS over edges loaded from the
database. At enterprise scale this becomes a recursive CTE, a graph database,
or a precomputed reachability index; the `resolve_path` contract stays the same.
"""

from dataclasses import dataclass, field
from fnmatch import fnmatchcase as fnmatch
from collections import deque
from datetime import datetime, timezone
from .config import settings

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AccessEdge, AccessNode, RelationshipSource

# Relations that transfer authority from a principal toward resources.
TRAVERSABLE = {
    "member_of",
    "assigned",
    "can_assume",
    "role_allows",
    "account_contains",
    "contains",
    "grants",
}


@dataclass
class AccessPath:
    """Proof of an authority path: ordered hops plus the actions it confers."""

    hops: list[dict] = field(default_factory=list)
    allowed_actions: list[str] = field(default_factory=list)

    def permits(self, action: str) -> bool:
        return any(fnmatch(action, pattern) for pattern in self.allowed_actions)

    def as_json(self) -> list[dict]:
        return self.hops


def get_node(db: Session, kind: str, name: str) -> AccessNode | None:
    return db.scalar(select(AccessNode).where(AccessNode.kind == kind, AccessNode.name == name))


def add_node(
    db: Session,
    kind: str,
    name: str,
    attrs: dict | None = None,
    *,
    tenant_id: str | None = None,
    external_id: str | None = None,
) -> AccessNode:
    node = AccessNode(
        kind=kind, name=name, attrs=attrs or {}, tenant_id=tenant_id, external_id=external_id
    )
    db.add(node)
    db.flush()
    return node


def add_edge(
    db: Session, src: AccessNode, relation: str, dst: AccessNode, attrs: dict | None = None
) -> AccessEdge:
    edge = AccessEdge(src_id=src.id, relation=relation, dst_id=dst.id, attrs=attrs or {})
    db.add(edge)
    db.flush()
    return edge


def resolve_path(
    db: Session, subject: str, action: str, resource: str, *, tenant: str | None = None
) -> AccessPath | None:
    """BFS from user:`subject` to asset:`resource`, collecting allowed actions
    from role_allows edges along the way. Returns proof or None.

    When `tenant` is given, only nodes belonging to that tenant (or to no
    tenant) are traversable - paths never cross tenant boundaries."""
    start = get_node(db, "user", subject)
    target = get_node(db, "asset", resource)
    if start is None or target is None:
        return None

    def in_tenant(node: AccessNode) -> bool:
        return tenant is None or node.tenant_id is None or node.tenant_id == tenant

    nodes = {n.id: n for n in db.scalars(select(AccessNode)).all() if in_tenant(n)}
    if start.id not in nodes or target.id not in nodes:
        return None
    now = datetime.now(timezone.utc)
    sources = {s.id: s for s in db.scalars(select(RelationshipSource)).all()}

    def fresh(record):
        if record.source_id is None:
            return settings.demo_enabled
        source = sources.get(record.source_id)
        if source is None or not source.enabled:
            return False
        if record.tenant_id != source.tenant_id:
            return False
        for stamp in (record.observed_at, source.last_sync_at):
            if stamp is None:
                return False
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
            if not 0 <= (now - stamp).total_seconds() <= settings.source_max_age_seconds:
                return False
        return True

    nodes = {key: node for key, node in nodes.items() if fresh(node)}
    if start.id not in nodes or target.id not in nodes:
        return None
    out_edges: dict[str, list[AccessEdge]] = {}
    edges = db.scalars(select(AccessEdge)).all()
    unsupported_sources = {e.source_id for e in edges if e.source_id and (
        e.attrs.get("conditions") or e.attrs.get("unsupported") or e.attrs.get("effect", "allow") != "allow")}
    for e in edges:
        if (e.relation in TRAVERSABLE and e.src_id in nodes and e.dst_id in nodes and fresh(e)
                and e.source_id not in unsupported_sources and not e.attrs.get("conditions") and e.attrs.get("effect", "allow") == "allow"
                and not e.attrs.get("unsupported")):
            out_edges.setdefault(e.src_id, []).append(e)

    # Breadth-first enumeration of simple paths (cycle check is per-path, not
    # global, so an alternate path that DOES confer the action is still found).
    MAX_DEPTH = 8
    queue = deque([(start.id, [])])
    expanded = 0
    while queue:
        expanded += 1
        if expanded > 10000:
            return None  # bounded search; no proof means no authority
        node_id, trail = queue.popleft()
        if node_id == target.id:
            actions = sorted(
                {a for e in trail if e.relation == "role_allows" for a in e.attrs.get("actions", [])}
            )
            path = AccessPath(
                hops=[
                    {
                        "src": f"{nodes[e.src_id].kind}:{nodes[e.src_id].name}",
                        "relation": e.relation,
                        "dst": f"{nodes[e.dst_id].kind}:{nodes[e.dst_id].name}",
                        **({"actions": e.attrs["actions"]} if "actions" in e.attrs else {}),
                    }
                    for e in trail
                ],
                allowed_actions=actions,
            )
            if path.permits(action):
                return path
            continue  # keep searching other paths
        if len(trail) >= MAX_DEPTH:
            continue
        on_path = {start.id} | {e.dst_id for e in trail}
        for e in out_edges.get(node_id, []):
            if e.dst_id not in on_path:
                queue.append((e.dst_id, trail + [e]))
    return None


def capability_path(
    db: Session, subject: str, capability: str, resource: str, *, tenant: str | None = None
) -> AccessPath | None:
    """Prove that `subject` holds a capability (e.g. "approval:rotate_secret"
    or "admin:audit:read") scoped to `resource`. Capabilities are modeled in
    the same graph as cloud actions but in distinct namespaces, so approval
    or admin authority never doubles as execution authority."""
    return resolve_path(db, subject, capability, resource, tenant=tenant)
