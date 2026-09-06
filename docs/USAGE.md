# Use and test EDA

Complete [installation](../INSTALL.md) first. Run the following commands from the repository root with the Python environment activated.

## What you can do now

The connected sandbox supports metadata discovery, graph synchronization, human identity mapping and diagnostic checks. It is not yet an agent-facing data retrieval product. There is no ready-made graph dashboard; `/docs` is an API reference.

## 1. Check local services

```bash
docker compose --env-file sandbox/.env -f sandbox/compose.yaml ps
curl --fail http://127.0.0.1:8000/readyz
```

The API and database should be healthy. The migration service is a one-time job; exit code 0 means success.

## 2. Import and verify real metadata

```bash
python sandbox/test_live_eda.py
```

Use an AWS CLI session allowed to assume the configured reader role. The helper keeps temporary role credentials in memory and passes them only to the short-lived operator container. It reads the Entra collector settings from your private configuration.

This command:

1. Checks readiness and refusal of anonymous/invalid authentication.
2. Imports Entra users/groups and AWS resource metadata into local PostgreSQL.
3. Compares stored facts with the connector's observations.
4. Injects a local import failure and verifies rollback preserves the prior snapshot.
5. Recollects and checks the audit hash chain.
6. Produces raw credential-redacted diagnostics and separate shareable outcomes.

It may update local inventory but does not modify cloud resources. Collection is per source: Entra can pass while AWS fails. Read every result rather than treating one success as proof of the whole setup.

Repeat the command after changing test data or refreshing expired credentials. There is no unattended synchronization scheduler. Evidence older than 15 minutes is treated as stale in this sandbox.

## 3. Test a human sign-in

After a successful sync:

```bash
docker compose --env-file sandbox/.env -f sandbox/compose.yaml run --rm sync python /sandbox/check-login.py
```

Follow the Microsoft device-code instructions as an enabled test user. The helper verifies the token and checks that it maps to the imported Entra identity; it does not print the token or grant resource access. If tenant policy disallows device-code flow, stop rather than weakening it. Interactive sign-in was not completed in the recorded 21-check run.

## 4. Understand access refusals

Sign-in is not authorization. Inventory imports do not create administrator or resource access grants. Calls to administrative graph/audit endpoints can correctly return 403 even after authentication because the connected sandbox does not automatically bootstrap those capabilities.

Do not invent relationships just to obtain an allow. Real Entra-to-AWS delegation, native permission rules and the required agent/user identity pair remain unfinished. The sandbox leaves cloud action execution in mock mode; the live test helper separately exercises the metadata role.

## 5. Read the reports

| Output | Purpose | Public? |
| --- | --- | --- |
| `private-test-results/<timestamp>/` | Raw stdout/stderr and HTTP diagnostics, with known credentials redacted | **No**; operational details can remain |
| `public-test-results/<timestamp>/` | Predefined check names and outcomes | Review before sharing |
| `public-evidence/<timestamp>/` | Local health and mocked Terraform evidence | Review before sharing |

To collect the last category from Git Bash:

```bash
bash sandbox/collect-public-evidence.sh
```

Nothing is published automatically. Do not attach `.env`, Terraform state/plans, real `.tfvars`, full Docker inspection output or raw terminal history. The checked-in [live test summary](LIVE_TEST_SUMMARY.md) contains sanitized conclusions only.

The standard live runner does not restart containers or remove memberships. The recorded supplementary restart and AWS content-denial checks were separate operator-run tests; do not assume a later standard run repeats those checks.

## 6. Relationship-change acceptance test

In the disposable tenant only, add a test user to a test group, synchronize, remove the membership and synchronize again. Compare the exact stored membership before/after and confirm unrelated facts remain. Terraform may restore memberships it manages on a later apply.

This scenario is still an operator acceptance procedure, not an automated live test. A provider-side revocation was not exercised in the recorded run. Likewise, absence of a discovered graph path does not prove that native cloud access is impossible.

## Developer/offline checks

```bash
python -m pytest -q beta/tests
terraform '-chdir=sandbox/entra' init -backend=false
terraform '-chdir=sandbox/entra' test
terraform '-chdir=sandbox/aws' init -backend=false
terraform '-chdir=sandbox/aws' test
```

Python tests use their own test database; Terraform tests use mocked providers. These are different evidence from live integration tests. Do not point test fixtures at a real data database.

For connector development, see [the SDK quickstart](CONNECTOR_QUICKSTART.md). For existing databases, read [migration guidance](MIGRATIONS.md) before changing schemas.
