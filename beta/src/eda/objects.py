"""Object inventory with independent per-object and field disclosure checks."""

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


def scoped_context(db: Session, *, grant: Grant, resource: str, max_hops: int = 2) -> dict:
    """Every root, neighbor, relationship and restricted field needs a live capability.

    Action grants establish the investigation session, not disclosure authority.
    No traversal through an undiscoverable object or undisclosable relationship.
    """
    from . import access_graph
    broker.validate_grant(grant, action=grant.scope["actions"][0], resource=resource)
    if not 0 <= max_hops <= 4:
        raise ValueError("context depth must be between 0 and 4")
    empty = {"root": resource, "nodes": [], "edges": [], "note": "context unavailable"}
    if not grant.tenant_id:
        return empty
    candidates = db.scalars(select(ObjectNode).where(ObjectNode.name == resource,
                                                     ObjectNode.tenant_id == grant.tenant_id).limit(2)).all()
    if len(candidates) != 1:
        return empty
    root = candidates[0]
    checked = {}

    def permits(node, capability):
        key = (node.id, capability)
        if key not in checked:
            checked[key] = access_graph.capability_path(db, grant.subject, capability, node.name,
                                                        tenant=grant.tenant_id) is not None
        return checked[key]

    if not permits(root, "context:discover"):
        return empty
    nodes = {root.id: root}
    distance = {root.id: 0}
    frontier = [root.id]
    visible_edges = {}
    for hop in range(1, max_hops + 1):
        next_frontier = []
        for node_id in frontier:
            from sqlalchemy import or_
            edges = db.scalars(select(ObjectEdge).where(or_(ObjectEdge.src_id == node_id,
                                                             ObjectEdge.dst_id == node_id)).limit(1001)).all()
            if len(edges) > 1000:
                raise ValueError("context expansion exceeds limit")
            for edge in edges:
                source = db.get(ObjectNode, edge.src_id)
                target = db.get(ObjectNode, edge.dst_id)
                if source is None or target is None:
                    continue
                if source.tenant_id != grant.tenant_id or target.tenant_id != grant.tenant_id:
                    continue
                if not permits(source, "context:discover") or not permits(target, "context:discover"):
                    continue
                if not permits(source, "context:relation:" + edge.relation):
                    continue
                other = target if source.id == node_id else source
                visible_edges[edge.id] = {"src": f"{source.kind}:{source.name}", "relation": edge.relation,
                                           "dst": f"{target.kind}:{target.name}"}
                if other.id not in distance:
                    distance[other.id] = hop
                    nodes[other.id] = other
                    next_frontier.append(other.id)
                    if len(nodes) > 1000:
                        raise ValueError("context exceeds object limit")
        frontier = next_frontier
    views = []
    for node_id in sorted(nodes, key=lambda key: (distance[key], nodes[key].name)):
        node = nodes[node_id]
        attrs = "REDACTED"
        if permits(node, "context:read"):
            restricted = set(node.attrs.get("restricted_fields", []))
            # Secret material never belongs in a metadata graph, including roots.
            restricted |= {"password", "secret", "secret_value", "token", "credentials", "private_key"}
            attrs = {key: (value if key not in restricted or permits(node, "context:field:" + key) else "REDACTED")
                     for key, value in node.attrs.items() if key != "restricted_fields"}
        views.append({"kind": node.kind, "name": node.name, "attrs": attrs, "distance": distance[node_id]})
    return {"root": f"{root.kind}:{root.name}", "nodes": views,
            "edges": sorted(visible_edges.values(), key=lambda edge: (edge["src"], edge["relation"], edge["dst"])),
            "scope": {"max_hops": max_hops, "read_only": grant.scope.get("read_only", False),
                      "disclosure": "explicit discover/read/relation/field capabilities"}}
