# Access relationships and connector SDK implementation plan

Current verified progress and remaining work are recorded in [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md). The sections below are the acceptance plan, not a claim of completed implementation. See [CONNECTOR_QUICKSTART.md](CONNECTOR_QUICKSTART.md) for the implemented registration and delivery workflow.

## Intended outcome

A connector can discover objects and permission evidence without changing the core. The platform can explain the supported authority for a request, reject incomplete/stale evidence, and remove access when the authoritative source removes it. Information disclosure is checked separately from mutation permission.

First scope: one customer deployment, one selected OIDC/directory provider, AWS IAM/S3/EC2 and PostgreSQL metadata/permissions. Metadata first; content remains at its source until authorized retrieval. Universally extensible does not mean that every provider's permissions are automatically understood.

## A1 — Stable contracts and tenant-safe identifiers

Dependencies: existing foundation.

Deliverables:
- Versioned schemas under contracts/ for objects, relationships, permission evidence, source manifests, sync events, and decisions.
- Common object identity based on tenant, source instance and stable native identifier; names are labels. Allow provider-specific typed extensions without erasing native metadata.
- Keep object relations (owns, contains, depends_on, derived_from) distinct from authority relations (member_of, assigned_role, grants_permission). Object relationships never automatically confer access.
- Permission evidence includes source, original-policy reference/digest, effect, conditions, resource scope, observation time, source version and expiry. Preserve unsupported native constructs.
- Define migration from current name/external-ID lookups to tenant/source-qualified keys, including collision report and backup/rollback procedure. Add appropriate constraints and foreign keys through Alembic.

Correctness gate:
- Same display name in two tenants or two sources does not collide.
- Rename preserves identity; unknown schema versions and malformed evidence are rejected.
- Populated database migration preserves existing demo relations; ambiguous mappings stop migration with a report rather than merging authority.
- Test actual PostgreSQL constraints and transaction behavior as well as local unit tests.

## A2 — Connector SDK and source assertion permissions

Dependencies: A1.

Deliverables:
- Python SDK backed by a language-neutral protocol. Optional capabilities: describe, check_connection, discover, read_relationships, read_permissions, read_changes(cursor), evaluate_access and fetch_context.
- Manifest declares supported objects/relations, native permission semantics, required source privileges, deletion support, version compatibility and completeness limitations.
- Shared pagination, retry/backoff, rate limits, bounded payloads, secret references, checkpoints and cancellation. Execution credentials and write handlers are outside the discovery SDK.
- Allow foreign-object references under explicit relation-specific rules. A directory connector can assert an approved federation assignment without gaining permission to rewrite AWS role policies.
- Conformance kit and a fixture connector demonstrating object and permission collection with no core edits.

Correctness gate:
- Add the fixture connector through registration only.
- Reject cross-tenant references, unauthorized relation types and source-owned object overwrites.
- A partial-permission source reports incomplete coverage rather than a complete empty inventory.
- Verify pagination, throttling, retry bounds, checkpoint resume, invalid configuration and accidental credential disclosure.

## A3 — Reliable synchronization and revocation

Dependencies: A1/A2.

Deliverables:
- Snapshot begin/page/complete protocol with snapshot scope and source generation; incomplete scans never imply deletion.
- Atomically publish a complete generation and remove missing source-owned facts within that scope. Concurrent source generations must not interleave into an invalid inventory.
- Incremental upsert/tombstone events; monotonic versions and explicit source-reset rules. Out-of-order events cannot resurrect deleted grants.
- Idempotency keys bound to payload digest, durable receipts and resumable checkpoints. Conflicting reuse is rejected.
- Per-fact expiry, source health and derivation dependencies. A heartbeat cannot refresh an obsolete membership. Expiry or removal invalidates affected cached decisions.

Correctness gate:
- Membership removal stops authorization while unrelated access remains valid.
- Interrupt every snapshot page and restart: no unintended deletions or duplicates.
- Replay, reorder and duplicate events; compare resulting facts with a simple reference model using property-based tests.
- Test concurrent snapshots, stale generations, future timestamps, disabled sources and cache invalidation.
- Measure event-delivery and reconciliation latency separately. Initial target: reflect supported source events within 60 seconds after collector receipt; report polling-only limitations explicitly.

## A4 — Verified identity links and authority evaluation

Dependencies: A3.

Deliverables:
- Bind issuer/subject to approved source mappings and canonical principals. Link directory identities, federated roles and database roles using authoritative provisioning/federation evidence.
- Never grant access from matching email/name, ownership or lineage. Ambiguity returns indeterminate and requires explicit resolution.
- Replace bare path/boolean results with allow/deny/indeterminate, evidence chain, policy version, source versions, expiry and coverage limitations.
- Native evaluators report applicable denies, inheritance, conditions and supported semantics. Unknown constructs or missing evidence cannot produce allow.
- Bounded graph queries with tenant filtering, runtime/expansion/result limits. A truncated search is not reported as complete proof.
- Revalidate evidence at use time; bind any cached decision to subject, action, target, inputs, policy/evidence versions and expiry.

Correctness gate:
- Negative cases: alternate issuer, same email, renamed principal, conflicting bindings, stale intermediate role edge, deny overriding allow, unsupported conditions, cyclic graph and traversal exhaustion.
- A valid root identity with stale downstream evidence still fails authorization.
- Differential tests against actual supported provider operations in a sandbox. Graph simulation alone is not the oracle for native permissions.
- Permission removal between decision and use prevents execution or disclosure.

## A5 — Authorized context retrieval

Dependencies: A4.

Deliverables:
- Separate discover/read/field-read/action permissions. Evaluate each root, neighbor, edge and field before disclosure, including names and existence.
- Metadata-only graph by default; approved detail retrieval through SDK capability.
- Permission/version-aware caches and response shaping that avoid hidden-object leaks.
- Lineage extensions can use OpenLineage concepts, but lineage adds no authority.

Correctness gate:
- Root mutation permission cannot read secret content.
- Hidden neighbors and restricted root fields remain hidden in APIs, summaries, errors and caches.
- Revocation invalidates previously permitted retrieval; cross-tenant cache keys cannot collide.

## A6 — Real connector proof

Dependencies: A2–A5. Fixture adapters can be developed earlier against A1 contracts.

Deliverables:
- One directory connector: users, groups, membership removals and approved federation links. Select the user's actual IdP before live qualification; use a fake source until then.
- AWS connector: IAM evidence, S3/EC2 metadata, account/region identifiers and explicit support matrix. Read-only inspection declares every API permission, not just its first call.
- PostgreSQL connector: schemas, tables, columns, roles and grants. Initially mark unsupported row-level security, ownership bypass, view/function and role-assumption semantics as indeterminate where they affect the requested action.
- Expose onboarding coverage, freshness and incomplete evidence to operators.

Correctness gate:
- Directory change alters the corresponding supported authority decision end to end.
- Supported AWS and PostgreSQL allow/deny cases agree with actual sandbox calls.
- A connector added through the SDK requires no core change; provider-specific facts survive normalization.
- A read-only collector cannot mutate source data or retrieve execution credentials.

## Integration with the remaining screenshot fixes

W1: Real broker/action adapter; trusted target-account role mapping, complete action permissions, native resource scoping, valid STS session naming, separate execution deadline and provider credential lifetime, explicit cancellation/revocation semantics. Gate: real sandbox calls, negative IAM tests, TTL constraints and activity-log correlation.

W2: Durable execution state machine and transactional outbox; approval consumption bound to immutable plan; idempotent dispatch, worker fencing and reconciliation. Gate: crash before/after every effect and commit, concurrent retry, queue redelivery and unknown provider outcome. No blind retries or universal exactly-once claims.

W3: Separate execution identity and isolated jobs with restricted filesystem, egress, resource use and typed/bounded output transport. Gate: attempted leakage through allowed fields/errors/network, job cancellation, expiry, arbitrary role selection and worker takeover.

W4: Independently pinned verification keys, immutable external anchors, rotation/continuity/freshness rules and cloud-native evidence reconciliation. Gate: chain/key replacement, truncation, missing anchors, old backup restore, simultaneous appends and anchor outage.

These remain production-write blockers. Production configuration stays gated until the required work is complete; read-only pilot release also requires A5 and appropriate audit durability.

## Review and implementation sequence

1. A1 contracts and migrations, then A2 fixture connector plus test kit.
2. A3 reconciliation and revocation, then A4 authority and identity evaluation.
3. A5 disclosure, then A6 real integration qualification.
4. Complete W1–W4 before enabling production mutation workflows.
5. Terraform packages the qualified services and trust boundaries; it cannot substitute for the preceding correctness work.

Every package has a separate reviewable diff, test results and updated status. Report implemented, fixture-tested and live-verified separately. Do not mark a package complete based only on its documentation or a green pre-existing suite.

## Completion demonstration for the two original issues

From a fresh test deployment, register a connector, synchronize a user/group/role/resource path and show its evidence. Perform a permitted read while hiding an unauthorized neighbor. Remove the membership upstream and show that the old decision and cached context no longer work. Interrupt and resume a snapshot without erasing unrelated facts. Introduce an unsupported policy condition and show indeterminate rather than allow. Add another connector without editing the core.

Live prerequisites: chosen IdP application and read-only directory access, an AWS sandbox with test resources and scoped roles, and a disposable PostgreSQL instance. Contract, fixture and reconciliation implementation can proceed before those are available. No cloud deployment or account mutation is authorized merely by this planning document.
