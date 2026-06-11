# EDA Control Plane

Reference implementation of the **Enterprise Data Access and Relationship Graph Architecture** — a local-first, governed enterprise control plane. The full design document lives in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

The core philosophy:

> Model authority, evaluate policy, broker temporary access, scope context, govern actions, audit everything, and let AI recommend — not enforce.

## Quickstart

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"

# run the end-to-end demo (the doc's "Cloud Investigation Request" scenario)
.\.venv\Scripts\python demo.py

# run the test suite
.\.venv\Scripts\python -m pytest

# run the HTTP API and explore it at http://127.0.0.1:8000/docs
.\.venv\Scripts\uvicorn eda.api:app --reload
```

Default storage is SQLite (zero infrastructure). For Postgres:

```powershell
docker compose up -d
$env:EDA_DATABASE_URL = "postgresql+psycopg2://eda:eda-dev-only@localhost:5432/eda"
.\.venv\Scripts\python -m pip install -e ".[postgres]"
.\.venv\Scripts\python -m eda.seed
```

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
| Request flow             | [gateway.py](src/eda/gateway.py)             | `POST /requests`, `POST /approvals/{id}/decision` |

## How the design principles show up in code

- **Authority before context** — [objects.py](src/eda/objects.py) refuses to return context without a validated grant; the gateway only reaches the object graph after the policy decision and broker step.
- **Separate access from ontology** — `access_nodes`/`access_edges` and `object_nodes`/`object_edges` are distinct graphs ([models.py](src/eda/models.py)); the access graph proves paths, the object graph explains meaning.
- **Temporary authority over standing privilege** — every grant is scoped to one action + one resource with a TTL capped by policy obligations ([broker.py](src/eda/broker.py)). `AwsStsBroker` shows the real `sts:AssumeRole` + session-policy seam.
- **Deterministic gates before action** — [policy.py](src/eda/policy.py) evaluates a closed set of condition keys against versioned policy documents. Deny > require_approval > allow; default deny. No model anywhere in the decision path.
- **Local-first by default** — SQLite/Postgres inside your boundary; no external calls anywhere in the codebase.
- **Audit everything** — one hash-chained record per outcome carrying identity, path proof, policy input/decision/version, approval, redacted grant, API calls, and context summary. `GET /audit/verify` walks the chain; tampering breaks it (proven in [test_audit.py](tests/test_audit.py)).
- **AI observes and proposes; deterministic systems approve and enforce** — [feedback.py](src/eda/feedback.py) analyzers only ever create `proposed` recommendations; a human decision (itself audited) is required, and applying a change is a separate versioned act. `NarrativeGateway` is the seam for a customer-hosted local model.

## Secure enterprise front

Identity and access relationships come from trusted enterprise inputs, not from callers:

- **OIDC authentication** — `EDA_AUTH_MODE=oidc` validates bearer tokens (Okta, Entra ID, Keycloak, any standard provider): JWKS signature, issuer, audience, expiry, stable subject, tenant, and MFA assurance from `amr`/`acr` claims. Callers cannot choose their identity, MFA status, or risk score; the dev session endpoint is disabled. See [.env.example](.env.example) for provider configuration.
- **Identity-to-graph mapping** — a verified token resolves as `issuer + subject → tenant + canonical external ID → existing AccessNode`. Unknown identities, tenant mismatches, and identities asserted by disabled or stale sources all fail closed before policy ever runs ([identity_providers.py](src/eda/identity_providers.py)).
- **Collector ingestion** — registered sources (e.g. `okta-directory-prod`) push relationship batches with a source-bound credential. Each source is confined to its namespace (`okta:`), so a collector can never write another tenant's or source's relationships. Batches are validated atomically (schema, kinds, relations, batch size) and every imported node/edge records `tenant_id`, `external_id`, `source_id`, and `observed_at` ([ingestion.py](src/eda/ingestion.py)).
- **Unchanged downstream** — imported relationships feed the existing path resolver; policy, broker, object graph, actions, and audit are untouched. Seeded identities remain available only to the dev provider for tests and local demos.

## Seeded example environment

Matches the design doc's example: `user:derrick → member_of group:security-engineers → assigned permission_set:prod-readonly → can_assume role:prod-security-auditor → role_allows ec2:Describe* → account:prod → asset:ec2-prod-1`, plus a privileged `prod-secops` path for rotation/containment, `marcus` (path but weak sessions), and `eve` (contractor, no path). The object graph models `payments-api`, its instance, VPC, secret, database, cardholder data, finding `F-2026-0142`, and incident `INC-42`. See [seed.py](src/eda/seed.py).

## What is real vs. mocked

Real: path resolution, policy evaluation, grant scoping/TTL/validation, approval workflow (with self-approval rejection), context scoping with sensitive-attribute redaction, hash-chained audit with tamper detection, feedback analyzers with human gating.

Real: OIDC token validation (full JWKS/issuer/audience/expiry/tenant/MFA verification — point it at a real Okta or Entra app), fail-closed identity mapping, and collector ingestion with namespace confinement and provenance.

Mocked/stand-in (each behind a production seam): the dev identity provider (tests/local demos only), cloud credentials (`MockStsBroker` → `AwsStsBroker`/GCP impersonation/Azure PIM), action handlers (mock API calls → real SDK calls inside the controlled runner), narrative summaries (templates → local LLM gateway).

Production hardening not included here: migrations (Alembic), external audit anchoring (object-lock / transparency log), approver authorization policies, rate limiting, mTLS between components, HA.
