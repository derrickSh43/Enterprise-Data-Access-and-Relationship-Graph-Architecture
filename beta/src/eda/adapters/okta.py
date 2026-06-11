"""Okta directory feed -> generic relationship batch.

Pure transforms over Okta API response shapes (no network here): a collector
fetches /api/v1/groups and each group's /users, then POSTs the result of
`directory_to_relationships` to its ingestion endpoint. Node IDs use the
"okta:" namespace, matching a source registered with allowed_namespace="okta:".

Other products (Entra, a CIEM export, an HR system) feed the same contract
with their own adapter.
"""

NAMESPACE = "okta"


def _eid(okta_id: str) -> str:
    return f"{NAMESPACE}:{okta_id}"


def directory_to_relationships(
    groups: list[dict], memberships: dict[str, list[dict]]
) -> list[dict]:
    """groups: Okta /api/v1/groups objects; memberships: group id -> list of
    /api/v1/groups/{id}/users objects. Returns user member_of group rows."""
    relationships = []
    for group in groups:
        target = {"kind": "group", "id": _eid(group["id"])}
        group_name = (group.get("profile") or {}).get("name", "")
        for user in memberships.get(group["id"], []):
            profile = user.get("profile") or {}
            relationships.append(
                {
                    "subject": {"kind": "user", "id": _eid(user["id"])},
                    "relation": "member_of",
                    "target": target,
                    "attributes": {
                        "group_name": group_name,
                        "user_login": profile.get("login", ""),
                    },
                }
            )
    return relationships


def group_role_assignments_to_relationships(assignments: list[dict]) -> list[dict]:
    """CIEM-style rows {group_id, permission_set_id} -> group assigned
    permission_set relationships (the seam for Okta IGA / Identity Security
    Posture or any CIEM export)."""
    return [
        {
            "subject": {"kind": "group", "id": _eid(row["group_id"])},
            "relation": "assigned",
            "target": {"kind": "permission_set", "id": _eid(row["permission_set_id"])},
            "attributes": row.get("attributes", {}),
        }
        for row in assignments
    ]
