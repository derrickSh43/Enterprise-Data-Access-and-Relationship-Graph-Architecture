# Implementation status

EDA is an experimental foundation for governed agent data access. A connected Entra/AWS/local PostgreSQL sandbox has live smoke-test evidence. Production startup remains blocked. The mandatory agent identity + authorizing user + scoped delegation model is not yet implemented.

| Area | Implemented | Evidence and limits |
| --- | --- | --- |
| Identity/configuration | OIDC verification, tenant/source binding, native-ID prefix mapping, ambiguous/stale identity rejection | Fixture tests; live authentication refusal tests. Interactive sign-in remains unverified. |
| Connector SDK | Versioned JSON contracts, Python interface and HTTP delivery client | Local tests; not a separately published standalone package or universal adapter catalog. |
| Synchronization | Source-owned snapshots, tombstones, sequence replay handling and freshness checks | Unit tests plus live import/reimport and controlled rollback against PostgreSQL. |
| Entra collection | Enabled users, groups and direct/nested user/group memberships | Live scan/import matched observed records. Provider-side revocation not exercised. |
| AWS collection | Bucket/IAM-role metadata and regional EC2 inventory | Live scoped role/import tests; target instance/bucket present. Complete native IAM evaluation absent. |
| PostgreSQL collector | Collector-visible schema/table/column metadata | Fixture-tested; source grants and row-level access evaluation absent. |
| Disclosure | Explicit discover/read/relationship/field capability checks | Local tests; not universal source-native row/field authorization. |
| Execution | Durable synchronous intent, replay handling and uncertain outcomes; limited EC2 read adapter | Fixture/local tests. Distributed dispatch/fencing and real write/compensation adapters absent. |
| Runner | Process runner and optional digest-pinned, network-disabled Docker runner | Local command/output tests; strong runtime isolation not qualified. |
| Audit | Hash-chain verification, independent configured key trust and local anchor checks | Live hash-chain checks. Immutable external publication/administration absent. |
| Deployment | Local Compose; Entra/AWS sandbox Terraform; larger infrastructure foundation | Sandbox is running and passed live checks. Full cloud app and Kubernetes deployment absent. |
| Agent delegation | Required design: every agent acts under a person's bounded authority | Not implemented; no autonomous agent-only authority model is intended. |

## Recorded evidence

- Earlier full local regression: 176 tests passed before the final sandbox additions.
- Subsequent targeted sandbox/identity/Entra checks: 43 passed.
- Connected sandbox run: 21 live/local checks passed, 4 areas not tested. See [sanitized summary](LIVE_TEST_SUMMARY.md).
- Both sandbox Terraform modules validate; 3 mocked plan tests pass.
- Final pre-publication local regression: 180 tests passed, with 2 dependency deprecation warnings. See [release notes](RELEASE_NOTES.md).

These test sets overlap and must not be added together. Test success does not certify production security, prove every upstream relationship is visible, or establish all native permissions. No hosted production application is being claimed.

## Remaining priorities

1. Carry and verify both agent/user identities and bounded, revocable task delegation.
2. Implement source-aware authorized data retrieval and supported native permission evaluators.
3. Add a durable collector spool and orchestration with bounded freshness guarantees.
4. Complete policy signing/lifecycle, execution fencing and provider outcome reconciliation.
5. Qualify isolation, immutable audit storage, backups/restore, load behavior and cloud deployment.
