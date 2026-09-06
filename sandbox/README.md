# Connected sandbox setup

Start with the repository [installation guide](../INSTALL.md), then follow [usage and testing](../docs/USAGE.md).

## Three primary setup files

- [entra/main.tf](entra/main.tf): applications, consent and test groups inside your existing Entra tenant.
- [aws/main.tf](aws/main.tf): small private AWS inspection sandbox and metadata role.
- [compose.yaml](compose.yaml): EDA, PostgreSQL and operator tools using [the Dockerfile](../deploy/Dockerfile).

Order: apply Entra and AWS (either order), run configure.py, start Docker Compose, then run test_live_eda.py. Configuration templates end in .example; keep real .env, .tfvars and state private.

## Operator tools

| Tool | Purpose |
| --- | --- |
| configure.py | Read Terraform outputs and create private local settings without printing secrets |
| test_live_eda.py | Acquire a temporary AWS reader session and run live metadata/identity-boundary checks |
| sync.py | Low-level transactional source import used by the operator tools |
| live_probe.py | Container-side import, rollback and optional permission test implementation |
| check-login.py | Interactive human sign-in and imported identity mapping |
| collect-public-evidence.sh | Git Bash launcher for allowlisted public evidence |
| public_evidence.py | Local health and mocked Terraform evidence, with raw outputs excluded |

The collector is an operator-run infrastructure tool, not an autonomous agent. The sandbox does not implement the required dual agent/user delegation or complete native permission evaluation. See [validation scope](VALIDATION.md).
