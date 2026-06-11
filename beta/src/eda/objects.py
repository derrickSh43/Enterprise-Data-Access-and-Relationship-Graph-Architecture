"""Object / Ontology Graph: what things are and how they connect.

Authority before context: this module refuses to answer without a validated
grant. Context is scoped - bounded hops from the target, and attributes of
sensitive-classified neighbors are summarized rather than returned in full
when the grant is read-only.
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import broker
from .models import Grant, ObjectEdge, ObjectNode


def get_object(db: Session, kind: str, name: str) -> ObjectNode | None:
    return db.scalar(select(ObjectNode).where(ObjectNode.kind == kind, ObjectNode.name == name))


def add_object(db: Session, kind: str, name: str, attrs: dict | None = None) -> ObjectNode:
    node = ObjectNode(kind=kind, name=name, attrs=attrs or {})
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


def _node_view(node: ObjectNode, *, read_only_scope: bool) -> dict:
    sensitive = node.attrs.get("classification") == "sensitive"
    if sensitive and read_only_scope:
        return {
            "kind": node.kind,
            "name": node.name,
            "classification": "sensitive",
            "attrs": "REDACTED (sensitive; grant is read-only scoped)",
        }
    return {"kind": node.kind, "name": node.name, "attrs": node.attrs}


def scoped_context(db: Session, *, grant: Grant, resource: str, max_hops: int = 2) -> dict:
    """Return the neighborhood of `resource`, only under a validated grant."""
    broker.validate_grant(grant, action=grant.scope["actions"][0], resource=resource)

    root = db.scalar(select(ObjectNode).where(ObjectNode.name == resource))
    if root is None:
        return {"root": resource, "nodes": [], "edges": [], "note": "object not modeled"}

    nodes = {n.id: n for n in db.scalars(select(ObjectNode)).all()}
    adjacency: dict[str, list[ObjectEdge]] = {}
    for e in db.scalars(select(ObjectEdge)).all():
        adjacency.setdefault(e.src_id, []).append(e)
        adjacency.setdefault(e.dst_id, []).append(e)  # traverse both directions

    read_only = grant.scope.get("read_only", False)
    seen = {root.id}
    edges_out: list[dict] = []
    frontier = [root.id]
    for _ in range(max_hops):
        next_frontier = []
        for node_id in frontier:
            for e in adjacency.get(node_id, []):
                other = e.dst_id if e.src_id == node_id else e.src_id
                edges_out.append(
                    {
                        "src": f"{nodes[e.src_id].kind}:{nodes[e.src_id].name}",
                        "relation": e.relation,
                        "dst": f"{nodes[e.dst_id].kind}:{nodes[e.dst_id].name}",
                    }
                )
                if other not in seen:
                    seen.add(other)
                    next_frontier.append(other)
        frontier = next_frontier

    unique_edges = [dict(t) for t in {tuple(sorted(e.items())) for e in edges_out}]
    return {
        "root": f"{root.kind}:{root.name}",
        "nodes": [_node_view(nodes[i], read_only_scope=read_only) for i in sorted(seen)],
        "edges": sorted(unique_edges, key=lambda e: (e["src"], e["relation"], e["dst"])),
        "scope": {"max_hops": max_hops, "read_only": read_only},
    }
