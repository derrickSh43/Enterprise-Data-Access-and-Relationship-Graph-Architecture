"""Microsoft Graph v1.0 users/groups/members collector.

Uses an injected Azure TokenCredential; credentials never enter fact envelopes.
Full scans only. PIM eligibility, applications/service principals, device access,
Azure RBAC and cloud federation assignments are not inferred from membership.
"""
from datetime import datetime, timezone
import json
import time
from urllib.parse import urlsplit, quote

from .sdk import Connector
from .contracts import Manifest, ObjectRecord, Reference, RelationshipRecord


class EntraConnector(Connector):
    def __init__(self, *, source_id, credential, client=None, sleep=time.sleep, max_pages=10000):
        if client is None:
            import httpx
            client = httpx.Client(timeout=30, follow_redirects=False)
        self.source_id, self.credential, self.client = source_id, credential, client
        self.sleep, self.max_pages = sleep, max_pages

    def describe(self):
        return Manifest(connector_type="entra", object_kinds=["user", "group"], relations=["member_of"],
                        capabilities=["snapshot"], permission_semantics="platform_relations",
                        limitations=["Enabled users and direct user/group membership only",
                                     "No PIM eligibility, service principals, Azure RBAC or cloud grants",
                                     "Hidden memberships require Member.Read.Hidden; access errors abort scan",
                                     "Microsoft Graph snapshots are not a transactional point-in-time view"])

    def check_connection(self):
        # Actual visibility is established by completing every paginated request.
        # Any permission/claim/HTTP failure prevents the complete event.
        self.credential.get_token("https://graph.microsoft.com/.default")
        return {"coverage": "complete", "scope": "enabled users and direct user/group membership"}

    def _pages(self, path):
        url = "https://graph.microsoft.com/v1.0/" + path
        seen = set()
        resource_path = urlsplit(url).path
        while url:
            parsed = urlsplit(url)
            if (parsed.scheme != "https" or parsed.netloc != "graph.microsoft.com"
                    or parsed.path != resource_path or parsed.fragment):
                raise ValueError("unsafe Microsoft Graph pagination target")
            if url in seen or len(seen) >= self.max_pages:
                raise ValueError("pagination loop or page limit reached")
            seen.add(url)
            for attempt in range(4):
                token = self.credential.get_token("https://graph.microsoft.com/.default").token
                with self.client.stream("GET", url, headers={"Authorization": "Bearer " + token},
                                        follow_redirects=False) as response:
                    if response.status_code in {429, 503} and attempt < 3:
                        try:
                            delay = min(30, max(0, int(response.headers.get("Retry-After", 2 ** attempt))))
                        except ValueError:
                            delay = 2 ** attempt
                        self.sleep(delay)
                        continue
                    if response.status_code != 200:
                        raise RuntimeError(f"Microsoft Graph collection failed (HTTP {response.status_code})")
                    chunks, size = [], 0
                    for chunk in response.iter_bytes():
                        size += len(chunk)
                        if size > 2 * 1024 * 1024:
                            raise ValueError("Microsoft Graph page exceeds size limit")
                        chunks.append(chunk)
                    data = json.loads(b"".join(chunks))
                    break
            if not isinstance(data, dict) or not isinstance(data.get("value"), list):
                raise ValueError("incomplete Microsoft Graph page")
            yield data["value"]
            url = data.get("@odata.nextLink")
            if url is not None and not isinstance(url, str):
                raise ValueError("invalid pagination cursor")

    def _ref(self, kind, native):
        return Reference(source_id=self.source_id, native_id="entra:" + native, kind=kind)

    def snapshot(self):
        users, disabled, groups = set(), set(), {}
        for rows in self._pages("users?$select=id,displayName,accountEnabled&$top=500"):
            objects = []
            for row in rows:
                if type(row.get("accountEnabled")) is not bool:
                    raise ValueError("accountEnabled unavailable; cannot establish identity state")
                native = row["id"]
                if native in users or native in disabled:
                    raise ValueError("duplicate user during scan; retry snapshot")
                if not row["accountEnabled"]:
                    disabled.add(native)
                    continue
                users.add(native)
                objects.append(ObjectRecord(ref=self._ref("user", native), display_name=row["displayName"],
                                            observed_at=datetime.now(timezone.utc)))
            yield objects, []
        for rows in self._pages("groups?$select=id,displayName,visibility&$top=500"):
            objects = []
            for row in rows:
                if row["id"] in groups:
                    raise ValueError("duplicate group during scan; retry snapshot")
                groups[row["id"]] = row
                objects.append(ObjectRecord(ref=self._ref("group", row["id"]), display_name=row["displayName"],
                                            observed_at=datetime.now(timezone.utc)))
            yield objects, []
        for native in groups:
            for rows in self._pages("groups/" + quote(native, safe="") + "/members?$select=id&$top=500"):
                relations = []
                for row in rows:
                    member = row["id"]
                    if member in disabled:
                        continue
                    kind = {"#microsoft.graph.user": "user", "#microsoft.graph.group": "group"}.get(row.get("@odata.type"))
                    if kind is None:
                        # Omitted types cannot confer authority in the supported model.
                        if "@odata.type" not in row:
                            raise ValueError("membership type unavailable")
                        continue
                    if (kind == "user" and member not in users) or (kind == "group" and member not in groups):
                        raise ValueError("directory changed during scan; retry snapshot")
                    relations.append(RelationshipRecord(subject=self._ref(kind, member), relation="member_of",
                        target=self._ref("group", native), observed_at=datetime.now(timezone.utc)))
                yield [], relations
