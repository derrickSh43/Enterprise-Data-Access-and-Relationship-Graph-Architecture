# EDA sandbox: live test report

**21 checks passed. No failures or blocked checks were recorded. Four areas remain untested.**

This run tested the live local EDA/PostgreSQL services and real Entra/AWS metadata reads. It did not change cloud users, groups, permissions or resources. It refreshed local inventory and restarted the two local services.

| What we tested | Result | What that means |
| --- | --- | --- |
| Application readiness | PASS | EDA responded successfully before and after restart. |
| Authentication boundaries | PASS | Anonymous requests, invalid tokens and the demo session-creation endpoint were refused. |
| Entra ingestion | PASS | Records stored in the graph exactly matched the connector's observations. Users and groups were present. |
| AWS ingestion | PASS | Imported metadata matched observations and included the expected sandbox instance and bucket. |
| AWS role scope | PASS | The session matched the intended account/role. Instance and security-group reads succeeded; reading the sample S3 file was denied. |
| Interrupted imports | PASS | A deliberately interrupted local import preserved the previous inventory and sequence. |
| Repeat imports | PASS | A second complete import matched the latest observation without duplicate stored facts. |
| Audit chain | PASS | The audit hash chain verified after both imports and after restart. |
| Restart recovery | PASS | PostgreSQL and EDA recovered; the live inventory checksum and count remained unchanged. |

## What is not proven yet

- Interactive human sign-in and mapping: not tested; requires a person to complete Microsoft sign-in.
- Provider-side membership revocation: not tested; no Entra memberships or user states were changed.
- Agent/user delegation: not implemented or tested by this setup.
- Native effective data permissions: not implemented or comprehensively tested. The S3 denial proves only this sandbox reader role's observed behavior.

The interrupted-import test is a controlled exception with transaction rollback, not a process kill or full crash-recovery test. Source-to-graph matching verifies ingestion fidelity, not that every provider relationship or permission is discoverable. Audit hash verification is not proof of immutable external storage. A successful repeat import is not a concurrency qualification.

## Evidence handling

- The local test runner produces predefined check-result files for sharing after review.
- Raw stdout/stderr and HTTP bodies are in a SEPARATE PRIVATE diagnostic bundle. Credentials were suppressed/redacted. Do not publish that private bundle: it may include operational identifiers or paths.

The public files contain no account IDs, tenant IDs, user identities, credentials, resource names, host paths or raw provider logs. Collection did not publish anything.
