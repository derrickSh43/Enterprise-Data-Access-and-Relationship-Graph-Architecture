"""Access Graph: discovers and proves authority paths.

It answers "what access paths exist?" - it does NOT make the final
authorization decision (that is the Policy Engine's job).

Reference implementation uses an in-Python BFS over edges loaded from the
database. At enterprise scale this becomes a recursive CTE, a graph database,
or a precomputed reachability index; the `resolve_path` contract stays the same.
"""

from dataclasses import dataclass, field
from fnmatch import fnmatch

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AccessEdge, AccessNode

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


def resolve_path(db: Session, subject: str, action: str, resource: str) -> AccessPath | None:
    """BFS from user:`subject` to asset:`resource`, collecting allowed actions
    from role_allows edges along the way. Returns proof or None."""
    start = get_node(db, "user", subject)
    target = get_node(db, "asset", resource)
    if start is None or target is None:
        return None

    nodes = {n.id: n for n in db.scalars(select(AccessNode)).all()}
    out_edges: dict[str, list[AccessEdge]] = {}
    for e in db.scalars(select(AccessEdge)).all():
        if e.relation in TRAVERSABLE:
            out_edges.setdefault(e.src_id, []).append(e)

    # Breadth-first enumeration of simple paths (cycle check is per-path, not
    # global, so an alternate path that DOES confer the action is still found).
    MAX_DEPTH = 8
    queue: list[tuple[str, list[AccessEdge]]] = [(start.id, [])]
    while queue:
        node_id, trail = queue.pop(0)
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
