# EDA Python implementation

For a first installation, use [the root installation guide](../INSTALL.md). For the connected sandbox, use [usage and testing](../docs/USAGE.md). Current capabilities and gaps are in [implementation status](../docs/IMPLEMENTATION_STATUS.md).

This package contains the Python reference implementation, connector interfaces, migrations and tests. It is not production-qualified. Agent/user delegation and complete native permission semantics are unfinished. The following technical reference includes prototype design material; current status takes precedence over architectural aspirations.

## Developer checks

From the repository root, create/activate a Python environment, then run:

```bash
python -m pip install -c beta/constraints-tested.txt -e './beta[dev,aws,entra,postgres]'
python -m pytest -q beta/tests
```

The demo uses mock authority and actions; it is separate from the connected Entra/AWS sandbox. Production startup remains blocked. Do not treat demo outcomes as live authorization evidence.

## Component map

| Architecture component   | Module                                       | HTTP surface                  |
| ------------------------ | -------------------------------------------- | ----------------------------- |
| Identity providers (OIDC + dev) | [identity_providers.py](src/eda/identity_providers.py) | bearer tokens on `/requests`, approvals, feedback; `POST /identity/sessions` (dev mode only) |
| Relationship ingestion   | [ingestion.py](src/eda/ingestion.py)         | `POST /relationship-sources/{id}/relationships` |
| Directory feed adapters  | [adapters/okta.py](src/eda/adapters/okta.py) | (transforms provider exports into the ingestion contract) |
| 1. Access Graph          | [access_graph.py](src/eda/access_graph.py)   | `GET /access-graph/path`      |
| 2. Policy Engine         | [policy.py](src/eda/policy.py)               | `GET /policy/active`, `POST /policy/evaluate` |
| 3. Authority Broker      | [broker.py](src/eda/broker.py)               | (internal; grants visible redacted in traces) |
| 4. Object/Ontology Graph | [objects.py](src/eda/objects.py)             | (context returned in request traces) |
| 5. Action/Workflow Layer | [actions.py](src/eda/actions.py)             | `GET /actions`                |
| 6. Audit/Evidence Layer  | [audit.py](src/eda/audit.py)                 | `GET /audit/records`, `GET /audit/verify` |
| 7. Local AI Feedback     | [feedback.py](src/eda/feedback.py)           | `POST /feedback/run`, `/feedback/recommendations` |
| Controlled runner        | [runner.py](src/eda/runner.py)               | (process-isolated execution for writes/high-risk actions) |
| Request flow             | [gateway.py](src/eda/gateway.py)             | `POST /requests`, `POST /approvals/{id}/decision` |
| Operations               | [docs/OPERATIONS.md](docs/OPERATIONS.md)     | `/healthz`, `/readyz`, `/metrics` |

## How the design principles show up in code

- **Authority before context** â€” [objects.py](src/eda/objects.py) refuses to return context without a validated grant; the gateway only reaches the object graph after the policy decision and broker step.
- **Separate access from ontology** â€” `access_nodes`/`access_edges` and `object_nodes`/`object_edges` are distinct graphs ([models.py](src/eda/models.py)); the access graph proves paths, the object graph explains meaning.
- **Temporary authority over standing privilege** â€” every grant is scoped to one action + one resource with a TTL capped by policy obligations ([broker.py](src/eda/broker.py)). `AwsStsBroker` shows the real `sts:AssumeRole` + session-policy seam.
- **Deterministic gates before action** â€” [policy.py](src/eda/policy.py) evaluates a closed set of condition keys against versioned policy documents. Deny > require_approval > allow; default deny. No model anywhere in the decision path.
- **Local-first by default** â€” SQLite/Postgres inside your boundary; no external calls anywhere in the codebase.
- **Audit everything** â€” one hash-chained record per outcome carrying identity, path proof, policy input/decision/version, approval, redacted grant, API calls, and context summary. `GET /audit/verify` walks the chain; tampering breaks it (proven in [test_audit.py](tests/test_audit.py)).
- **AI observes and proposes; deterministic systems approve and enforce** â€” [feedback.py](src/eda/feedback.py) analyzers only ever create `proposed` recommendations; a human decision (itself audited) is required, and applying a change is a separate versioned act. `NarrativeGateway` is the seam for a customer-hosted local model.

## Secure enterprise front

Identity and access relationships come from trusted enterprise inputs, not from callers:

- **OIDC authentication** â€” `EDA_AUTH_MODE=oidc` validates bearer tokens (Okta, Entra ID, Keycloak, any standard provider): JWKS signature, issuer, audience, expiry, stable subject, tenant, and MFA assurance from `amr`/`acr` claims. Callers cannot choose their identity, MFA status, or risk score; the dev session endpoint is disabled. See [.env.example](.env.example) for provider configuration.
- **Identity-to-graph mapping** â€” a verified token resolves as `issuer + subject â†’ tenant + canonical external ID â†’ existing AccessNode`. Unknown identities, tenant mismatches, and identities asserted by disabled or stale sources all fail closed before policy ever runs ([identity_providers.py](src/eda/identity_providers.py)).
- **Collector ingestion** â€” registered sources (e.g. `okta-directory-prod`) push relationship batches with a source-bound credential. Each source is confined to its namespace (`okta:`), so a collector can never write another tenant's or source's relationships. Batches are validated atomically (schema, kinds, relations, batch size) and every imported node/edge records `tenant_id`, `external_id`, `source_id`, and `observed_at` ([ingestion.py](src/eda/ingestion.py)).
- **Unchanged downstream** â€” imported relationships feed the existing path resolver; policy, broker, object graph, actions, and audit are untouched. Seeded identities remain available only to the dev provider for tests and local demos.

## Beta hardening

The beta work plan layered fifteen hardening packages onto the front door, preserving the request flow:

- **Approval authorization** ([gateway.py](src/eda/gateway.py)) â€” approving is its own authorization decision: the approver must hold a proven access path conferring the server-derived `approval:<action>` capability for the target resource (preserved as evidence on the approval record), capability namespaces never double as execution authority, and self-approval stays rejected.
- **Approval replay prevention** â€” approvals are bound to the exact request (subject, action, resource, inputs hash), expire (`EDA_APPROVAL_TTL`), and are consumed atomically exactly once via compare-and-swap.
- **Action/resource compatibility + typed inputs** ([actions.py](src/eda/actions.py)) â€” actions declare supported resource kinds and providers (inspecting a secret with an EC2 action is rejected before policy), and every action has a strict pydantic input schema: types, length bounds, unknown-field rejection.
- **Disclosure control** ([objects.py](src/eda/objects.py)) â€” root authority doesn't authorize the neighborhood: sensitive neighbors are redacted at one hop and omitted beyond, `restricted_fields` are masked on every non-root node, and other tenants' objects are invisible.
- **Admin endpoint authorization** ([api.py](src/eda/api.py)) â€” policy, access-graph, audit, feedback, and metrics surfaces require proven `admin:<area>:<verb>` capability paths; authentication alone gets a 403.
- **Credential storage + lifetime consistency** ([broker.py](src/eda/broker.py)) â€” credentials live in the broker vault; the database holds an opaque reference. Provider credential lifetime may never exceed the grant lifetime (the AWS adapter refuses sub-900s grants), and revocation clears both systems at once.
- **Controlled runner** ([runner.py](src/eda/runner.py)) â€” a real process boundary: credentials confined to the job process, wall-clock timeouts with termination, output-size caps, and only declared output keys returned (exfiltration attempts are stripped â€” tested).
- **Audit hardening** ([audit.py](src/eda/audit.py)) â€” appends are serialized with a DB-level unique-predecessor backstop (no competing chain heads), and chain heads are Ed25519-signed and anchored to an external trust domain so even a full chain recompute by a DBA is detectable.
- **Tenant isolation** â€” tenant scope on nodes, edges, objects, approvals, grants, audit records, and recommendations; access paths never cross tenants; audit and recommendation queries are filtered to the caller's tenant.
- **Policy lifecycle** ([policy.py](src/eda/policy.py)) â€” propose (validated + simulated) â†’ activate (audited) â†’ rollback; active documents are checksummed, so a direct database edit fails closed at evaluation.
- **Analyzer accuracy + operations** â€” least-privilege analysis normalizes identifiers and matches wildcards before flagging unused authority; health/readiness/metrics endpoints, collector idempotency keys, and [docs/OPERATIONS.md](docs/OPERATIONS.md) cover backup, restore, recovery, and key management.

## Seeded example environment

Matches the design doc's example: `user:derrick â†’ member_of group:security-engineers â†’ assigned permission_set:prod-readonly â†’ can_assume role:prod-security-auditor â†’ role_allows ec2:Describe* â†’ account:prod â†’ asset:ec2-prod-1`, plus a privileged `prod-secops` path for rotation/containment, `marcus` (path but weak sessions), and `eve` (contractor, no path). The object graph models `payments-api`, its instance, VPC, secret, database, cardholder data, finding `F-2026-0142`, and incident `INC-42`. See [seed.py](src/eda/seed.py).

## What is real vs. mocked

Real: path resolution, policy evaluation, grant scoping/TTL/validation, approval workflow (with self-approval rejection), context scoping with sensitive-attribute redaction, hash-chained audit with tamper detection, feedback analyzers with human gating.

Real: OIDC token validation (full JWKS/issuer/audience/expiry/tenant/MFA verification â€” point it at a real Okta or Entra app), fail-closed identity mapping, collector ingestion with namespace confinement and provenance, capability-based approval authorization with single-use replay-proof approvals, process-isolated controlled execution, vaulted credentials with lifetime consistency, per-node disclosure control, capability-gated admin surfaces, tenant isolation, checksummed policy lifecycle, and signed audit anchoring.

Mocked/stand-in (each behind a production seam): the dev identity provider (tests/local demos only), cloud credentials (`MockStsBroker` â†’ `AwsStsBroker`/GCP impersonation/Azure PIM), action handlers (mock API calls â†’ real SDK calls inside the controlled runner), narrative summaries (templates â†’ local LLM gateway), the in-memory credential vault (â†’ Vault/KMS), and the anchor file (â†’ object-lock storage / transparency log).

Remaining production work (documented in [docs/OPERATIONS.md](docs/OPERATIONS.md)): Alembic migrations, OS-level runner resource limits (job objects/cgroups), Prometheus metrics export, rate limiting, mTLS between components, HA.
