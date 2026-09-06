# EDA implementation, correctness, and deployment roadmap

Status: proposed implementation plan; no cloud resources provisioned.
Baseline reviewed: 79b32bd5a56574b1f2f67f5d6abc74036dda943c.

## Outcome and scope

Deliver a customer-owned governed investigation platform: authenticate, resolve evidence-backed authority, disclose approved context, approve bounded actions, execute with temporary credentials, and preserve independently verifiable evidence. AI receives authorized context and proposes recommendations only.

First supported deployment: one customer per AWS deployment, one OIDC identity provider, AWS IAM/S3/EC2 and PostgreSQL connectors. Keep tenant identifiers and isolation in the model; shared multi-customer hosting is a later qualification milestone. Local-first means enterprise context stays inside the customer's chosen boundary, including backups, logs, model inference, and telemetry. It does not imply that cloud or identity APIs require no network access.

Use Terraform for infrastructure and immutable container releases for software. Start with PostgreSQL for both logically separate graphs. Introduce a dedicated graph engine only if representative benchmarks justify it. Evaluate OpenFGA for platform relationship authorization through an adapter and an architecture decision record; do not make it a substitute for native IAM semantics.

## Non-negotiable correctness properties

1. A discovered relationship is evidence, not an unconditional access grant. Unsupported or incomplete permission semantics produce indeterminate, which cannot authorize execution.
2. No authority is inferred from display names, matching email addresses, ownership, lineage, or network reachability alone.
3. Every authorizing dependency has a trusted source, version, tenant, and freshness bound. Revocation invalidates dependent decisions and caches.
4. Disclosure, field access, and mutation are distinct permissions. Root access does not confer neighborhood or secret-content access.
5. Every external operation has durable intent before execution. Retries cannot blindly repeat an operation whose outcome is uncertain.
6. Approvals bind the exact plan, actor, target, inputs, justification, expiry, and relevant policy/action versions. Revalidate authority and mutable conditions immediately before execution.
7. Collectors, API, broker, and runners have separate credentials and privileges. Model output never grants authority.
8. Audit verification uses independently trusted keys and continuity expectations. Missing evidence cannot be reported as successful verification.
9. Production cannot start in demo mode, with unknown authentication configuration, mock execution, or absent required trust configuration.

## Work packages and exit gates

Each package should be a separately reviewable change with its own migration, tests, documentation, and rollback notes where applicable. Preserve existing behavior unless the package explicitly changes its contract.

### P0 — Baseline, threat model, and test harness

Dependencies: none.

Implement:
- Record supported environments, deployment boundary, trust domains, actor types, threat assumptions, and supported native permission semantics.
- Capture the current demo and test suite as a baseline. Pin tested dependencies and runtime versions; add reproducible CI and package builds.
- Create fixtures for two tenants, repeated display names, conflicting grants, conditional denies, stale sources, and malicious metadata.
- Define a coverage report distinguishing implemented, mocked, unsupported, and live-verified capabilities.
- Assign an owner to each package and approve initial capacity/freshness targets before performance qualification.

Test/gate: baseline tests pass in a clean environment; fixtures are independent of developer paths and credentials; CI publishes the exact revision and environment used. No claim of cloud correctness based only on mocks.

### P1 — Production configuration, persistence, and identity

Dependencies: P0.

Implement:
- Explicit dev/test/production modes; reject unknown auth modes; disable demo seeding and dev token issuance in production.
- Validate OIDC issuer, audience, algorithms, tenant rules, token purpose, and provider-specific MFA assurance. Represent unavailable risk as unknown; define policy for unknown risk rather than hardcoding zero.
- Require an independently controlled bootstrap/admin enrollment process with an audited break-glass procedure. Do not bootstrap authority through arbitrary imported metadata.
- Add Alembic migrations and tenant-qualified unique identifiers, foreign keys, and indexes. Replace name-only lookups. Remove implicit null-tenant sharing; model shared objects explicitly.
- Apply database tenant isolation where appropriate, including tests with pooled connections and background jobs. Scope policies and admin capabilities explicitly.

Test/gate: reject invalid tokens, signing-key changes outside policy, wrong audiences/tenants, ambiguous identities, unknown risk for restricted actions, and all production demo configurations. Test migrations on populated databases and tenant isolation with identical names across tenants. Missing active policy in production fails closed.

### P2 — Connector protocol and SDK

Dependencies: P1.

Implement:
- Versioned JSON schemas and a Python SDK, with a language-neutral protocol for later SDKs.
- Common object envelope: canonical_id, tenant_id, source_instance_id, native_id, kind, parent_id, display_name, classification, observed_at, source_version, attributes.
- Relationship envelope: subject_id, relation, object_id, permission/effect/conditions where applicable, source_id, evidence_ref, observed_at, valid_until, version, observed-or-derived status.
- Optional capabilities: describe, check_connection, discover, read_relationships, read_permissions, read_changes(cursor), evaluate_access, fetch_context. Keep execution in a separate adapter contract.
- Manifests declare permissions needed, object/relation types, coverage, unsupported semantics, deletion support, schema versions, and supported provider versions.
- Source registration constrains object ownership and allowed relationship assertions. Foreign-object references are allowed only under explicit relation-specific rules; a directory connector cannot rewrite cloud policies.
- Reusable pagination, retries with jitter, rate-limit handling, checkpointing, secret references, size bounds, cancellation, and structured diagnostics.
- Starter connector, authoring guide, recorded sanitized fixtures, and conformance test kit.

Test/gate: a sample connector loads without core changes. Reject invalid schemas, unknown protocol versions, cross-source overwrites, unauthorized relation types, namespace collisions, oversized payloads, and cross-tenant references. A source's limited visibility is reported as incomplete, never as a complete empty inventory.

### P3 — Synchronization, reconciliation, and identity linking

Dependencies: P2.

Implement:
- Durable ingestion receipts binding idempotency key to payload digest; reject key reuse with a different payload.
- Snapshot begin/page/complete protocol; delete missing source-owned facts only after successful completion and only within declared snapshot scope.
- Explicit tombstones for incremental removal; monotonic versions, late-event handling, replay rules, and conservative handling of implausible timestamps.
- Preserve source facts separately from derived edges; store derivation dependencies and evidence. Invalidate caches and derived facts when sources change or expire.
- Identity linking through verified federation/provisioning identifiers and approved mappings; ambiguous matches require resolution, never automatic privilege merging.
- Independently check freshness of every fact used in an authority path. Source heartbeat does not refresh old facts.

Test/gate: pagination interruption does not delete valid objects; complete snapshots remove missing relationships; out-of-order events do not resurrect revoked access; duplicate deliveries do not duplicate facts. Group removal, disabled source, and expired downstream role evidence all stop authorization. Property-based event-sequence tests compare final state with a reference model.

### P4 — Effective authority and policy lifecycle

Dependencies: P3.

Implement:
- Structured allow/deny/indeterminate decisions with evidence, reasons, supported semantics, source versions, evaluated_at, and expiry.
- Provider-specific permission evaluation contracts preserving raw policy evidence, explicit denies, inheritance, conditions, boundaries, and unsupported constructs.
- Keep business policy, platform relationship authorization, and native permission enforcement distinct. Use exact service semantics for action matching instead of generic OS-dependent glob behavior.
- A signed/versioned decision envelope binds subject, target, action, validated inputs, justification, graph evidence, policy version, and expiry. Broker validates the binding and rejects stale decisions.
- Signed policy releases or independently protected policy digests; checksums stored beside editable policies alone are not protection against a database administrator. Propose, simulate, review, activate, rollback, and audit.
- Bound graph query depth, runtime, result size, and expansion count; use tenant-filtered SQL and indexes instead of loading entire graphs. Explain coverage limits when traversal is incomplete.

Test/gate: compare supported cases with actual sandbox provider decisions, including negative cases and conditions. Unsupported semantics never yield allow. Test policy precedence, rollback, tampered policy plus recomputed checksum, race-time policy changes, and graph cycles/fan-out. Revoked approver authority invalidates execution under an old approval.

### P5 — Object context and retrieval authorization

Dependencies: P4.

Implement:
- Separate discover/read/field-read/action permissions for roots, neighbors, relationships, and fields; treat identifiers and relationship existence as potentially sensitive.
- Metadata-first inventory; authorized detail retrieval on demand. No default copying of table rows, file content, or secret values into the graph.
- Enforce source permissions plus platform policy for each disclosure; do not treat classification or distance as a sufficient authorization rule.
- Bind caches to identity/tenant, permission and source versions, and expiry. Make response shaping and errors avoid existence leaks.
- Add lineage ingestion through OpenLineage-compatible mapping; lineage never transfers authority.

Test/gate: users cannot discover unauthorized neighbor names, infer hidden relationships through responses, read restricted root fields, or obtain cached content after revocation. Rotating a secret does not imply reading it. Verify outbound model context and audit summaries for forbidden content.

### P6 — Real connectors and provider adapters

Dependencies: P2–P5; adapter development may proceed alongside P3/P4 using the fixed contracts.

Implement:
- One OIDC/directory integration with users, groups, membership changes, and federation links.
- AWS IAM plus S3/EC2 inventory, native identifiers, account/region boundaries, policy evidence, and declared evaluation coverage.
- PostgreSQL schemas/tables/columns/roles/grants; account for role inheritance and expose unsupported row-level, view, or function semantics as indeterminate until implemented.
- Real read-only inspection: declare every required API permission, correct resource addressing, session names/tags/source identity, pagination, and response filters.
- Handle APIs that cannot scope to an individual resource with a bounded trusted runner and explicit account/region restrictions; never claim finer native enforcement than AWS provides.
- Default cloud broker becomes explicitly configured in production. Distinguish execution deadline from provider credential lifetime: AWS STS minimum is 900 seconds, while a job may have a shorter authorized window.
- Separate local cancellation/vault deletion from provider revocation; implement containment and record the residual credential validity window.

Test/gate: real sandbox login and sync; live inspection matches expected source inventory and respects denies. All API calls fit the declared action permission set. Native lifetime constraints, throttling, provider outages, partial inventory visibility, pagination, and credential expiry have tested outcomes. No production write enabled yet.

### P7 — Durable approvals and execution

Dependencies: P4–P6.

Implement:
- Durable execution state machine: requested, awaiting_approval, authorized, queued, running, succeeded, failed, cancelled, outcome_unknown, reconciled.
- Transactionally persist approval consumption, execution intent, and an outbox record before dispatch. Queue delivers references, not credential material.
- Idempotency binds logical operation ID to an immutable plan. Workers use leases/fencing and provider idempotency tokens when supported. Reconcile unknown results before retry; do not promise universal exactly-once cloud execution.
- Revalidate subject and approver authority, policy, plan, expiry, and target preconditions immediately before the effect.
- Strongly isolate write runners with a separate identity, bounded resources, minimal filesystem, restricted egress, no host mounts, short job windows, typed outputs, bounded transport, and secret redaction across outputs/errors/API evidence.
- Broker releases only job-scoped credentials to the runner; API and collectors cannot fetch them. Terminate jobs on cancellation; use a provider-specific revocation/containment strategy where needed.
- Add one reversible sandbox action with explicit preconditions, postconditions, blast-radius bounds, and compensation. Rollback is a tested operation with its own authorization, not a descriptive string.

Test/gate: inject process/DB/queue/network failures before and after each transition. Concurrent retries and approval reuse do not duplicate supported effects. Crash after provider success is reconciled. Timeout may mean unknown outcome and never implies rollback. Test malicious output in allowed keys, stderr, oversized messages, network exfiltration, expiry, lease loss, and cancellation.

### P8 — Durable audit and independent trust

Dependencies: P1; integrate fully with P7 before writes are released.

Implement:
- Record durable intent and decision before effects, then append outcomes and reconciliation evidence. Capture decision/action/source versions, approval binding, provider request IDs, context disclosure manifest, and correlation identifiers with sensitive values redacted.
- Database-serialized chain append with bounded retry; test multiple processes against PostgreSQL. Commit visibility and lock scope must cover the transaction, not only flush.
- Independent signing/verification trust: trusted key registry, versioned keys, rotation history, immutable anchor storage, freshness and continuity checks, and expected minimum anchor counts.
- Use a separate audit account or independently administered bucket/key policy for production. Audit writer cannot delete retained anchors. Missing/stale/truncated anchors cause verification failure or an explicit unavailable state.
- Reconcile cloud-native activity logs with execution records; a handler's self-reported API list is not sufficient evidence.

Test/gate: simultaneous appends preserve one chain; modifications, truncation, recomputation, replacement signing keys, missing files/objects, replayed anchors, and interrupted signing fail verification. Restore old backups and show safe reconciliation with newer anchors. Anchor outage blocks new writes according to the documented durability/freshness policy.

### P9 — Operator experience and optional AI

Dependencies: P5, P6, P8; action UI additionally depends on P7.

Implement:
- Guided source onboarding showing required privileges, connection status, last complete sync, coverage limitations, and unresolved identity mappings.
- Investigation UI: search permitted objects, explain access with evidence freshness, inspect dependencies, preview an action, request approval, and track execution/evidence.
- Admin UI for policy proposals and simulation; controlled bootstrap and break-glass recovery instructions.
- Optional customer-hosted model gateway: authorized retrieval, no execution credentials, no external context egress, provenance-linked summaries, and recommendations that require separate policy-controlled application.
- Feedback recommendations use normalized permissions and actual observed coverage; distinguish unobserved activity from unnecessary authority.

Test/gate: realistic operator walkthrough from onboarding to investigation and approval. Denied searches and summaries reveal no hidden objects. Prompt injection in source metadata cannot change policy or execute tools; unsupported summary claims are flagged or withheld. Core investigation works with AI disabled.

### P10 — Terraform deployment and release automation

Dependencies: scaffold after P1; release qualification requires P6–P9, with AI optional.

Implement the AWS architecture and deployment flow below. Include health/readiness covering critical dependencies, bounded-cardinality metrics, tracing, rate limits, certificate rotation, alarms, backup/restore, and upgrade runbooks. Document required outbound identity/provider endpoints; enforce allowed egress using appropriate network controls rather than assuming security groups filter domain names.

Test/gate: clean deployment, second no-change plan, upgrade with populated data, failed migration rollback procedure, backup restore, dependency outages, certificate/key rotation, and operator recovery all pass in a sandbox account. Validate both pilot and production profiles. Publish measured costs and capacity assumptions before enabling a production profile.

## AWS reference deployment

Terraform provisions:
- Existing-VPC integration by default for enterprise installs, with an optional new-VPC module. Private application/data subnets and internal HTTPS load balancer; customer supplies private connectivity, DNS, and OIDC prerequisites.
- ECS Fargate services for API/UI and workers, separately scoped collector tasks, and one short-lived task per controlled write job. Broker is a separate trust boundary with narrowly scoped assume-role permission.
- RDS PostgreSQL with encryption, backups, migration role separate from runtime role; Multi-AZ in the production profile.
- SQS dispatch queue and dead-letter queue, with a PostgreSQL transactional outbox as the durable dispatch source. Duplicate delivery is expected and handled by P7.
- ECR image repositories; immutable image digests; distinct task execution roles and application roles.
- Secrets Manager secret references and KMS keys. Runtime identity retrieves permitted secrets; keep plaintext out of Terraform variables/state wherever supported.
- Immutable S3 audit anchors, preferably in a separate audit account with separate administration; CloudWatch logs/alarms, provider activity logging configuration, and backup controls.
- Encrypted/versioned S3 Terraform backend with lockfile-based locking and tightly scoped access. Bootstrap backend separately and keep its state independent from application teardown.

Fargate task isolation improves the execution boundary, but connector/action code remains trusted and reviewed. Restrict task role assignment and task-definition overrides so jobs cannot choose a broader role. Do not run arbitrary third-party code or AI-generated code in the execution path.

Profiles:
- local: Docker Compose plus PostgreSQL, explicit demo mode, no Terraform or AWS required.
- aws-pilot: private single-customer deployment, smaller capacity, read-only actions enabled initially, visible availability limitations.
- aws-production: redundant services, Multi-AZ database, independent audit trust, restore evidence, tightened operational policies, write actions enabled only after qualification.

Optional AI is off by default. A customer-hosted model endpoint is configured separately; GPU hosting is a later optional module because it materially changes deployment complexity and cost.

## Proposed repository structure

```text
beta/src/eda/                 existing core, incrementally hardened
sdk/python/                  connector SDK and conformance kit
contracts/                   versioned object, relation, action, decision schemas
connectors/{directory,aws,postgres}/
deploy/compose/               local development and demonstration
infra/bootstrap/              backend and deployment identity
infra/modules/{network,compute,database,queue,identity,audit,observability}/
infra/environments/{pilot,production}/
tests/{contract,integration,security,fault,performance,deployment}/
docs/{architecture-decisions,connectors,operations,release-evidence}/
```

## Installation and upgrade experience

1. Preflight checks AWS identity, permissions, quotas, region, network/DNS/certificate, OIDC configuration, audit account access, and connector prerequisites. Report missing requirements with actionable messages.
2. Bootstrap remote state and short-lived deployment identity once. Prefer CI federation over stored AWS access keys.
3. Select a versioned release and profile; supply documented non-secret configuration and secret references. Review Terraform plan and cost estimate.
4. Apply infrastructure pinned to reviewed module/provider versions and application image digests. Do not run database migrations through Terraform local-exec provisioners.
5. Release pipeline runs an explicit migration task with a lock, then rolls out compatible application services and smoke tests. Use expand/contract schema changes; application rollback and database recovery are separate procedures.
6. Initialize the first administrator through the documented trusted bootstrap process; onboard collectors; run the bundled read-only acceptance scenario.
7. Produce an installation report containing release/configuration identifiers, connector coverage/freshness, health, audit verification, and enabled actions.

A wrapper command can orchestrate these steps later, but must display the plan and preserve errors and recovery instructions. Pilot cleanup deletes disposable compute; data, backups, audit retention, and remote state have explicit preservation/decommission policies. Do not assume terraform destroy can or should remove retained evidence.

## Correctness test strategy

PR checks: unit and property tests for security invariants; SDK contract tests; PostgreSQL integration tests for constraints, isolation, and concurrency; migration checks; dependency/secret scanning; Terraform formatting/validation and plan assertions. Mocked infrastructure tests verify configuration, not actual cloud behavior.

Sandbox release checks: real IdP/cloud/database integration; deploy both profiles; verify IAM negative cases, TLS/network reachability, queue redelivery, grants, audit anchoring, and teardown/preservation rules. Run terraform test apply tests only in isolated accounts with budget and cleanup controls.

Fault qualification: kill workers at every execution boundary; lose database/queue/IdP/anchor connectivity; expire and revoke evidence; replay events and approvals; delay provider responses; restore an earlier database snapshot. Verify durable, explainable outcomes and no blind retry of uncertain effects.

Security qualification: adversarial tenant/source/identity collisions, stale authority, forged anchors/policies, disclosure inference, credential leakage, malicious connector payloads, compromised runner blast radius, and broker confused-deputy attempts. Independent review is a production-write release gate.

Performance qualification: select an agreed fixture size and tenant fan-out, then measure ingestion throughput, snapshot duration, graph query bounds, authorization p95/p99, queue delay, and audit contention under concurrent traffic. Distinguish internal policy latency from live provider latency. Replace whole-graph scans before claiming enterprise capacity.

Proposed initial pilot targets, to confirm before qualification:
- Incremental revocation reflected within 60 seconds of a supported source event reaching the collector; alert separately on upstream delivery delay. Poll-only sources disclose their measured worst-case interval.
- Evidence older than its source/action freshness budget cannot authorize writes.
- Internal authorization p95 below 500 ms at an explicitly documented pilot dataset/load; remote calls measured separately.
- No unauthorized disclosure or duplicated effect in the supported negative/fault test corpus. This is an acceptance result, not a proof for every possible execution.
- Disaster recovery target RPO <= 15 minutes and RTO <= 60 minutes, verified by a timed restore exercise; unresolved executions reconciled against independent evidence before writes resume.

Every release publishes test revision, environment, provider versions, supported semantics, failures/exclusions, restore evidence, and enabled action list. A green unit suite alone never enables production writes.

## Delivery milestones

M1: secure foundation and SDK (P0–P3). Exit: a new connector can be added without core changes; source removals and tenant identity collisions are handled correctly.

M2: deployed read-only investigation pilot (P4–P6, P8, basic P9/P10). Exit: clean Terraform deployment, real identity and data, truthful authority explanations, scoped context, and verified evidence. No cloud mutations enabled.

M3: controlled sandbox writes (P7 plus completed P8/P10 fault testing). Exit: approved reversible action, durable recovery and reconciliation, restricted runner, no duplicate supported effects under retries.

M4: production qualification (all required gates, independent security review, restore/upgrade/load evidence). Exit: an operator follows the installation runbook without code edits and safely upgrades/restores the deployment. AI remains optional.

M5: expansion after measured pilot results. Add connectors through the SDK, richer lineage, customer-hosted AI, alternate hosting targets, and shared multi-tenant operation only after their own correctness qualification.

Do not assign calendar commitments until staffing, identity provider, pilot account, supported action, expected inventory size, audit-account arrangement, and network constraints are known. The dependency order and exit gates above define the implementation sequence independently of staffing.

## Primary references

- Terraform S3 backend and locking: https://developer.hashicorp.com/terraform/language/backend/s3
- Terraform sensitive and ephemeral values: https://developer.hashicorp.com/terraform/language/manage-sensitive-data
- Terraform tests: https://developer.hashicorp.com/terraform/tutorials/configuration-language/test
- ECS task roles and isolation: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html
- Fargate security: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/fargate-security-considerations.html
- AWS STS constraints: https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
- AWS role-session revocation: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html
- OpenFGA concepts: https://openfga.dev/docs/concepts
- OpenLineage specification: https://github.com/OpenLineage/OpenLineage/blob/main/spec/OpenLineage.md

Implementation must verify current provider behavior against these primary references and real sandbox tests; this document does not itself certify any deployment.
