# Sandbox foundation update

## What changed

- Added versioned connector contracts, source-owned reconciliation, HTTP delivery, Entra/AWS/PostgreSQL metadata adapters and source-qualified identity mapping.
- Added bounded disclosure checks, audit trust hardening, durable synchronous execution intent and limited read/runner foundations.
- Added versioned database migrations, local Docker packaging, connected Entra/AWS Terraform sandbox and private/public evidence tools.
- Replaced the landing README with a plain-language project explanation. Added an ordered installation guide and a separate usage guide.
- Kept local credentials, real account settings, Terraform state, database files, raw logs and the account-specific troubleshooting helper out of Git.

## Verification

- Full local Python regression: **180 passed**, 2 dependency deprecation warnings (Windows/Python 3.13).
- Terraform mock tests: **6 passed** across Entra sandbox, AWS sandbox and the larger platform foundation.
- Primary documentation links and staged-file whitespace checked.
- Separate live sandbox evidence: **21 passed**, with explicit untested areas in [LIVE_TEST_SUMMARY.md](LIVE_TEST_SUMMARY.md).

These counts cover different overlapping test sets and should not be added together. Remote CI results must be checked separately after publication. No production readiness, dual-identity delegation or comprehensive native permission evaluation is claimed.
