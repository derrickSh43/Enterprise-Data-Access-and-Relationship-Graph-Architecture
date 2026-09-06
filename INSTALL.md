# Install the connected EDA sandbox

This guide uses **Git Bash on Windows**, from the repository root. It sets up the small inventory sandbox, not a production service. Commands that create cloud resources require your review and may incur charges.

## Install order

```text
Install local tools and clone the repository
          |
Configure Entra test tenant + AWS sandbox account
          |       (either order)
Generate sandbox/.env from both Terraform outputs
          |
Start local PostgreSQL, run migrations, start EDA
          |
Import metadata and run the live tests
```

Docker Desktop can be installed and started before either cloud setup. The connected Compose configuration needs the `.env` produced after both Terraform applies.

## 1. Prerequisites

- Git, Python 3.11 or later, Terraform 1.10 or later, Azure CLI and AWS CLI v2.
- Docker Desktop running **Linux containers**. See [Docker's Windows installation guide](https://docs.docker.com/desktop/setup/install/windows-install/).
- An existing disposable **Entra test tenant** and an administrator permitted to create apps/groups and consent to the requested Microsoft Graph permissions. This Terraform module does not create a tenant or user accounts.
- An existing **AWS sandbox account** and an authenticated CLI identity authorized to provision the resources in the reviewed plan.
- At least one enabled Entra test user you can sign into. Existing user object IDs can be assigned to the new test groups.

Use synthetic data. Keep state and credentials in a private, access-controlled directory rather than a shared or publicly synchronized folder.

## 2. Clone and prepare Python

```bash
git clone https://github.com/derrickSh43/Enterprise-Data-Access-and-Relationship-Graph-Architecture.git
cd Enterprise-Data-Access-and-Relationship-Graph-Architecture
python -m venv .venv
source .venv/Scripts/activate
python -m pip install -c beta/constraints-tested.txt -e './beta[dev,aws,entra,postgres]'
```

On Linux/macOS, activate with `source .venv/bin/activate`. The recorded local test platform is Windows/Python 3.13; CI also defines Linux and Python 3.11 checks. A configured CI matrix is not evidence that remote CI has completed.

## 3. Configure and apply Entra

Sign in to your test tenant, then copy the template:

```bash
az login --tenant YOUR-TENANT-ID --allow-no-subscriptions
cp -n sandbox/entra/sandbox.tfvars.example sandbox/entra/sandbox.tfvars
```

Edit `sandbox/entra/sandbox.tfvars`:

- `tenant_id`: the existing test tenant's UUID.
- `test_user_object_ids`: existing test users to add to the sandbox group; use object IDs, not email addresses.
- `collector_secret_expires_at`: a short **future** RFC3339 expiry. The template date is an example, not a permanent default.

```bash
terraform '-chdir=sandbox/entra' init
terraform '-chdir=sandbox/entra' plan '-var-file=sandbox.tfvars'
terraform '-chdir=sandbox/entra' apply '-var-file=sandbox.tfvars'
```

Wait for **Apply complete!** The module creates separate API, interactive-login and collector apps, two nested test groups and Graph read consent. The collector can read users and group memberships throughout this test tenant, not just the new groups. It is not given directory-write permissions. Hidden-membership visibility is not requested; a scan that cannot establish its required visibility must fail.

The generated expiring collector secret is sensitive **and is stored in Terraform state**. Do not copy outputs into chat, screenshots or public logs.

## 4. Configure and apply AWS

Sign in with your normal AWS CLI profile. Check the exact identity and account locally:

```bash
aws sts get-caller-identity
cp -n sandbox/aws/sandbox.tfvars.example sandbox/aws/sandbox.tfvars
```

Edit `sandbox/aws/sandbox.tfvars`:

- `expected_account_id`: your 12-digit sandbox account ID.
- `trusted_principal_arn`: the exact **existing IAM user or role ARN** for the identity that will run collection. A user ARN contains `user/`; a role ARN contains `role/`.
- Keep `run_instance = false` initially to minimize charges.

If your caller ARN contains `arn:aws:sts::...:assumed-role/...`, use the underlying IAM role's ARN, including its full path. Retrieve it from IAM rather than guessing. Do not use a root ARN. The collector role being created is different from the existing identity it trusts.

```bash
terraform '-chdir=sandbox/aws' init
terraform '-chdir=sandbox/aws' plan '-var-file=sandbox.tfvars'
terraform '-chdir=sandbox/aws' apply '-var-file=sandbox.tfvars'
```

Wait for **Apply complete!** The instance is briefly launched, then stopped by default. It has no public IP and its security group has no ingress/egress rules. The metadata reader can list buckets/roles and describe EC2 resources in the selected region; it cannot read S3 file contents or modify resources.

Do not run the broader `infra/platform` module for this installation. Set billing alerts separately; this module does not assume a notification address or enforce a spending cap.

## 5. Generate the local settings file

Once **both** Terraform applies have completed:

```bash
python sandbox/configure.py
```

Expected: **Created sandbox/.env**. The helper reads Terraform outputs and generates the database password and persistent audit signing key without printing secrets. It refuses to overwrite existing settings.

If `.env` already exists, keep it. To rotate an expired collector secret, update only that setting securely; do not regenerate the database password for an existing PostgreSQL volume. Never run an unfiltered `docker compose config` for a screenshot: it expands secrets.

## 6. Start Docker services

Start Docker Desktop and wait for its engine, then run:

```bash
docker compose --env-file sandbox/.env -f sandbox/compose.yaml config --quiet
docker compose --env-file sandbox/.env -f sandbox/compose.yaml up --build -d api
docker compose --env-file sandbox/.env -f sandbox/compose.yaml ps
curl --fail http://127.0.0.1:8000/readyz
```

Compose uses **`deploy/Dockerfile`** to build EDA. PostgreSQL starts first, the migration service completes, and then EDA starts. The migration container exiting with code 0 is expected.

Open **http://127.0.0.1:8000/docs** for the API reference. This is not a finished end-user dashboard. Readiness confirms local service health; it does not prove cloud connections work.

## 7. Connect and test

With your AWS CLI login still available:

```bash
python sandbox/test_live_eda.py
```

This operator-run tool acquires a temporary metadata-reader role, imports real Entra/AWS observations, verifies stored records, tests local interruption rollback and writes separate private/public reports. It does not grant an agent access or mutate cloud resources. See [Using EDA](docs/USAGE.md) for interpretation, interactive sign-in and repeat collection.

## Common setup errors

| Error | What to do |
| --- | --- |
| Terraform: too many command-line arguments | Keep the arguments quoted as shown, especially in PowerShell. |
| Invalid principal in IAM trust policy | Use the exact existing IAM user/role ARN. Do not label a user as a role. Fix the variable and reapply; preserve state. |
| Output `local_settings` unavailable | The relevant Terraform apply did not finish in that module. Finish it before running configure.py. |
| `.env` not found | Generate it after both cloud modules succeed. Do not proceed to Compose after a failed configuration step. |
| Cannot connect to Docker engine | Start Docker Desktop with Linux containers and wait until ready. |
| AWS credentials unavailable/expired | Renew your CLI login/profile in the same terminal used to run tests. |
| Entra import fails | Check collector-secret expiry, tenant IDs and admin consent. Do not add write privileges to fix a read failure. |
| User does not map | Synchronize first; verify the correct tenant and enabled user. Source evidence expires after 15 minutes. |

## PowerShell equivalents

Activate with `.\.venv\Scripts\Activate.ps1`. Use `Copy-Item` instead of `cp -n` only when the destination does not already exist. The quoted Terraform and Docker commands above also work in PowerShell. Use `Invoke-RestMethod http://127.0.0.1:8000/readyz` for the health check.

## Stop or remove the sandbox

```bash
docker compose --env-file sandbox/.env -f sandbox/compose.yaml down
```

This preserves local volumes. To remove cloud resources, review each destroy plan and run `terraform '-chdir=sandbox/aws' destroy '-var-file=sandbox.tfvars'` and the corresponding Entra command. Keep state until teardown completes. Untracked S3 objects intentionally block bucket deletion. Existing Entra users and the tenant are not deleted. Do not add `down -v` unless you intend to delete the local database/evidence volumes.
