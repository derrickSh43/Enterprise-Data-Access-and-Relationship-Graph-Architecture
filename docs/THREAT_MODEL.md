> Historical foundation threat model. For current coverage and remaining risks, see [implementation status](IMPLEMENTATION_STATUS.md). Planned items below describe the initial baseline, not the latest completion state.

# Initial threat model and capability coverage

Scope: foundation increment against baseline 79b32bd. This is a starting threat model, not production certification.

## Trust boundaries

- Caller to API: caller-controlled action, resource, inputs and justification. Only a verified identity provider establishes identity. A signed claim still needs type and tenant validation.
- Identity provider to graph: identity mapping must be unique and tenant-qualified. Complete issuer-to-source binding is outstanding; source freshness is currently a source-level check.
- Collector to graph: source permissions constrain assertions. Cross-source reference rules, deletions, complete snapshots and per-edge freshness remain outstanding.
- Graph/policy to broker: current in-process invocation needs a bound, signed decision contract before distributed deployment.
- Broker to runner: current mock credentials and subprocess runner are reference implementations; a subprocess with the host identity is not the production isolation boundary.
- Database to audit trust: current checksum/hash-chain controls do not defeat an attacker able to rewrite all local trust material. Independent pinned verification and immutable anchors remain outstanding.
- Graph to user/model: current classification filtering is incomplete authorization. AI must never receive privileged credentials or change authorization.

## Actors and security expectations

| Actor or failure | Expected property | Current coverage |
| --- | --- | --- |
| Caller supplies malformed or wrong-tenant token | Deny before mapping | Regression-tested with signed fixtures |
| Operator misspells authentication mode | Startup fails before database initialization | Regression-tested |
| Source maps same identity ambiguously | Deny rather than choose first row | Regression-tested |
| Provider supplies no risk assessment | Preserve unknown; default denies writes/sensitive reads | Regression-tested; existing stored policies need lifecycle update |
| Connector omits revoked membership | Removed authority cannot persist | Planned reconciliation package |
| Caller probes neighboring objects | No unauthorized disclosure, including identifiers | Planned disclosure package |
| Worker crashes after provider success | Reconcile without blind duplicate mutation | Planned durable execution package |
| DBA replaces chain and anchor key | Independent verifier rejects | Planned independent audit trust package |
| Compromised action code | Bound filesystem/network/credential blast radius | Planned isolated runner package |
| Deployment has unsafe reference adapters | Production startup fails | Regression-tested release gate |

## Current release coverage

OIDC signatures and claims, policy, approvals and graph flow are exercised locally with fixtures. Cloud actions and broker credentials remain simulated. No real AWS account, external IdP, PostgreSQL isolation, Terraform deployment, recovery objective or scale target is verified in this increment. Production remains disabled.

## Decisions still required

Choose the first IdP and token-purpose contract; establish trusted issuer/source mappings and bootstrap administrators; agree source freshness budgets and native IAM support; set pilot inventory/load targets; provision separate audit administration; define restricted egress and backup retention. These do not block implementing the versioned SDK and conformance kit.
