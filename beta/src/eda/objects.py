"""Object / Ontology Graph: what things are and how they connect.

Authority before context: this module refuses to answer without a validated
grant. Authorization of the root object does NOT authorize everything
connected to it - each returned node, edge, and field gets its own
disclosure decision:

- root node: full attributes (the grant covers it);
- sensitive-classified neighbors one hop out: listed, attributes redacted;
- sensitive-classified objects further out: omitted entirely, along with
  their edges;
- field-level: attribute keys named in a node's `restricted_fields` are
  redacted on every non-root node;
- tenant: objects belonging to a different tenant than the grant are
  invisible (objects with no tenant are shared infrastructure).
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import broker
from .models import Grant, ObjectEdge, ObjectNode


def get_object(db: Session, kind: str, name: str) -> ObjectNode | None:
    return db.scalar(select(ObjectNode).where(ObjectNode.kind == kind, ObjectNode.name == name))


def get_object_by_name(db: Session, name: str) -> ObjectNode | None:
    return db.scalar(select(ObjectNode).where(ObjectNode.name == name))


def add_object(
    db: Session, kind: str, name: str, attrs: dict | None = None, *, tenant_id: str | None = None
) -> ObjectNode:
    node = ObjectNode(kind=kind, name=name, attrs=attrs or {}, tenant_id=tenant_id)
    db.add(node)
    db.flush()
    return node


def relate(
    db: Session, src: ObjectNode, relation: str, dst: ObjectNode, attrs: dict | None = None
) -> ObjectEdge:
    edge = ObjectEdge(src_id=src.id, relation=relation, dst_id=dst.id, attrs=attrs or {})
    db.add(edge)
    db.flush()
    return edge


def _is_sensitive(node: ObjectNode) -> bool:
    return node.attrs.get("classification") == "sensitive"


def _node_view(node: ObjectNode, *, is_root: bool, distance: int) -> dict | None:
    """Per-node disclosure decision: full view, redacted view, or None (omit)."""
    if is_root:
        return {"kind": node.kind, "name": node.name, "attrs": node.attrs, "distance": 0}
    if _is_sensitive(node):
        if distance > 1:
            return None  # connected is not authorized; too far to even list
        return {
            "kind": node.kind,
            "name": node.name,
            "classification": "sensitive",
            "attrs": "REDACTED (sensitive; root-object authority does not extend here)",
            "distance": distance,
        }
    restricted = set(node.attrs.get("restricted_fields", []))
    attrs = {
        k: ("REDACTED" if k in restricted else v)
        for k, v in node.attrs.items()
        if k != "restricted_fields"
    }
    return {"kind": node.kind, "name": node.name, "attrs": attrs, "distance": distance}


def scoped_context(db: Session, *, grant: Grant, resource: str, max_hops: int = 2) -> dict:
    """Return the neighborhood of `resource`, only under a validated grant,
    with per-node/edge/field disclosure decisions applied."""
    broker.validate_grant(grant, action=grant.scope["actions"][0], resource=resource)

    root = get_object_by_name(db, resource)
    if root is None:
        return {"root": resource, "nodes": [], "edges": [], "note": "object not modeled"}

    def tenant_visible(node: ObjectNode) -> bool:
        return node.tenant_id is None or node.tenant_id == grant.tenant_id

    nodes = {n.id: n for n in db.scalars(select(ObjectNode)).all() if tenant_visible(n)}
    if root.id not in nodes:
        return {"root": resource, "nodes": [], "edges": [], "note": "object not visible"}
    adjacency: dict[str, list[ObjectEdge]] = {}
    for e in db.scalars(select(ObjectEdge)).all():
        if e.src_id in nodes and e.dst_id in nodes:
            adjacency.setdefault(e.src_id, []).append(e)
            adjacency.setdefault(e.dst_id, []).append(e)  # traverse both directions

    # BFS with hop tracking for distance-based disclosure
    distance = {root.id: 0}
    frontier = [root.id]
    edges_seen: list[ObjectEdge] = []
    for hop in range(1, max_hops + 1):
        next_frontier = []
        for node_id in frontier:
            for e in adjacency.get(node_id, []):
                other = e.dst_id if e.src_id == node_id else e.src_id
                edges_seen.append(e)
                if other not in distance:
                    distance[other] = hop
                    next_frontier.append(other)
        frontier = next_frontier

    # Per-node disclosure; omitted nodes (None) drop out along with their edges
    views: dict[str, dict] = {}
    for node_id, dist in distance.items():
        view = _node_view(nodes[node_id], is_root=(node_id == root.id), distance=dist)
        if view is not None:
            views[node_id] = view

    visible_edges = {
        (e.src_id, e.relation, e.dst_id)
        for e in edges_seen
        if e.src_id in views and e.dst_id in views
    }
    edges_out = [
        {
            "src": f"{nodes[s].kind}:{nodes[s].name}",
            "relation": r,
            "dst": f"{nodes[d].kind}:{nodes[d].name}",
        }
        for (s, r, d) in sorted(
            visible_edges, key=lambda t: (nodes[t[0]].name, t[1], nodes[t[2]].name)
        )
    ]

    return {
        "root": f"{root.kind}:{root.name}",
        "nodes": [views[i] for i in sorted(views, key=lambda i: (distance[i], nodes[i].name))],
        "edges": edges_out,
        "scope": {
            "max_hops": max_hops,
            "read_only": grant.scope.get("read_only", False),
            "disclosure": "per-node; sensitive neighbors redacted at 1 hop, omitted beyond",
        },
    }
