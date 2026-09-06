# Microsoft Entra ID connector

Implemented against Microsoft Graph v1.0 with an injected Azure TokenCredential. Tested with HTTP fixtures and a live sandbox import. Interactive sign-in and provider-side revocation remain unverified.

Install `.[entra]`. Construct EntraConnector with an explicitly tenant-bound Azure credential and an HTTP client, then feed collect_snapshot messages to the registered source's `/sync` endpoint. Persist every acknowledged sequence; on failure, abort the active snapshot before restarting at the next sequence. Never log or persist access tokens in inventory.

Register a source with namespace `entra:` and approve the connector manifest administratively. For OIDC, set provider prefix `entra`, external identity claim `oid`, tenant claim `tid`, and an explicit tenant-specific issuer/audience. Microsoft's pairwise `sub` is not the directory object ID. Stable tenant binding remains required.

Coverage: enabled users, groups and direct user/group memberships, including nested groups. Full scans only. Unsupported: PIM eligibility, service principals, Azure RBAC, cross-cloud assignments and effective resource grants. These memberships alone do not authorize cloud operations.

Request read-only Graph application permissions appropriate to users, groups and membership. Hidden membership needs Member.Read.Hidden. Reading accountEnabled requires the permissions documented by Microsoft; missing account state or any collection failure aborts the scan rather than certifying completeness. Final tenant permissions and consent must be validated against live Microsoft documentation and a test tenant before rollout.

References:
- https://learn.microsoft.com/en-us/graph/api/group-list-members?view=graph-rest-1.0
- https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0

Microsoft Graph directory scans are not atomic across pages. Unknown referenced users/groups or duplicate records abort a scan; repeated reconciliation and short freshness budgets are still needed to bound directory drift. Service-principal limitations in the v1.0 membership API do not establish complete workload identity coverage.

Configure EDA_OIDC_DIRECTORY_SOURCE to this connector source ID. This deployment-owned issuer/directory binding strips the configured provider prefix before matching native oid values and excludes other sources with the same native ID. See CONNECTOR_QUICKSTART.md.

For the included Entra collector, set EDA_OIDC_NATIVE_ID_PREFIX=entra: along with the pinned source. Its native identifiers include that prefix. The connected sandbox sets both automatically; see ../sandbox/README.md.
