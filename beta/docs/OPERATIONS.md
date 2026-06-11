# Operations

How to run, observe, back up, and recover the EDA control plane. This is a
reference implementation: each section names what is implemented here and what
a production deployment substitutes.

## Health and readiness

- `GET /healthz` — liveness, no dependencies, unauthenticated.
- `GET /readyz` — readiness; executes `SELECT 1` against the database.
- `GET /metrics` — request counters by method/path/status. Requires the
  `admin:metrics:read` capability (admin surfaces are capability-gated, not
  just authenticated).

## Schema management

The reference implementation creates tables with `Base.metadata.create_all`
(`eda.db.init_db`), which only adds missing tables — it never alters existing
ones. For production:

1. Adopt Alembic (`pip install alembic`, `alembic init migrations`), point
   `target_metadata` at `eda.db.Base.metadata`, and generate the initial
   revision with `alembic revision --autogenerate`.
2. Replace `init_db()` in the API lifespan with `alembic upgrade head` in the
   deploy pipeline.
3. Never edit `policy_records` or `audit_records` directly: active policies
   are checksummed (a direct edit fails closed at evaluation) and audit rows
   are hash-chained (an edit breaks `GET /audit/verify`).

## Idempotency and retries

- Collector batches: send an `Idempotency-Key` header with
  `POST /relationship-sources/{id}/relationships`. Replaying the same key
  returns the original summary without reapplying the batch, so collectors
  can retry on timeouts safely.
- Audit appends are serialized in-process; the unique constraint on
  `prev_hash` is the cross-process backstop. A writer that loses the race
  receives an `IntegrityError` and should retry its transaction.
- Governed requests (`POST /requests`) are not idempotent by design — each
  attempt is its own audited decision. Approvals are single-use and bound to
  the exact request, so retrying an allowed write requires a new approval.

## Background work

The feedback analyzers (`POST /feedback/run`) are an on-demand batch job in
the reference implementation. In production, schedule them (cron, Temporal,
Argo) with the same capability-gated service identity, and treat analyzer
runs as idempotent: fingerprints prevent duplicate recommendations.

## Backup and restore

SQLite (default): stop the service, copy the `.db` file, and copy the audit
anchor file (`EDA_AUDIT_ANCHOR_PATH`) — they back up the same trust state and
should be captured together.

Postgres: `pg_dump --serializable-deferrable` for consistent logical backups;
anchor file backed up separately from the database host (that separation is
the point of anchoring).

Restore procedure:
1. Restore the database.
2. Run `GET /audit/verify` — the hash chain must be intact.
3. Run `GET /audit/anchors/verify` — every anchored head must still match.
   A clean chain with failing anchors means the restored database is not the
   one that was anchored (stale backup or tampering); reconcile before
   resuming service.
4. Brokered credentials do not survive a restart (the vault is in-memory and
   grants are short-lived); in-flight grants simply expire. Re-issue via new
   requests.

## Key management

- `EDA_TOKEN_SECRET` — dev-mode session HMAC. Irrelevant in OIDC mode.
- `EDA_AUDIT_ANCHOR_KEY` — hex-encoded 32-byte Ed25519 seed for signing chain
  heads. If unset, an ephemeral per-process key is generated (anchors then
  verify only within that process lifetime — fine for tests, not for real
  use). Store the configured seed in a secret manager; rotate by starting a
  new anchor file and recording the rotation in the audit log.
- Collector secrets are stored hashed (SHA-256); the plaintext is shown once
  at registration. Rotate by registering a replacement source and disabling
  the old one (disabled sources fail closed for both ingestion and identity
  mapping).

## Recovery behavior

- **Audit chain broken** (`/audit/verify` not ok): treat as an incident. The
  `first_broken_seq` identifies the earliest tampered record; everything
  before it is still trustworthy, everything after needs reconciliation
  against anchors and upstream system logs (CloudTrail, IdP logs).
- **Active policy fails integrity** (requests denied with "policy
  integrity"): someone edited the active document outside the lifecycle.
  Roll back via `POST /policy/rollback` (re-activates the previous version
  with a fresh checksum) and investigate.
- **Stale relationship source** (identities stop resolving): the collector
  has not synced within `EDA_SOURCE_MAX_AGE`. This is fail-closed by design;
  fix the collector, re-sync, and access resumes.
- **Runner timeouts**: the job process is terminated and the request is
  audited as an error; nothing is partially returned. Retry as a new request.

## Tracing

Every request flow carries a `correlation_id` through the trace response, all
audit records, grants, and approvals. `GET /audit/records/{correlation_id}`
reconstructs the full decision chain. For distributed tracing, propagate the
correlation ID into broker/runner spans (OpenTelemetry middleware is a
straightforward addition; not included here).

## Known gaps (deliberate, reference-level)

- Alembic migrations documented but not wired (create_all suffices for the
  single-node reference).
- The credential vault is in-memory: restart drops issued credentials
  (acceptable for short-lived grants; production uses Vault/KMS).
- Runner enforces wall-clock timeout and output-size caps; CPU/memory limits
  need job objects (Windows) or cgroups (Linux) in the production seam.
- Metrics are in-memory counters, reset on restart; production exports to
  Prometheus.
