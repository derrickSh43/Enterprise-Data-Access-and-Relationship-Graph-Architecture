# Beta Implementation Work Plan

This document tracks the implementation issues to address after the secure enterprise front door is in place. The front door covers trusted identity verification, canonical identity mapping, and secure relationship ingestion. The existing authority-first architecture remains intact.

## 1. Approval Authorization

Approval must be a separate authorization decision, not simply a decision made by any user other than the requester.

- Define server-derived capabilities using `approval:<action_name>`, such as `approval:rotate_secret`.
- Store the required approval capability on the approval record. Clients must not provide or override it.
- Model approver authority in the existing access graph using principals, groups, permission sets, roles, capabilities, and resource scopes.
- Keep approval authority separate from action-execution authority.
- Require a proven access path showing that the approver has the required approval capability for the target resource.
- Preserve the approver access path as decision evidence.
- Retain self-approval rejection.
- Seed representative approval relationships for tests; production relationships should arrive through the secure relationship feed.

## 2. Action and Resource Compatibility

Actions must declare the resource types and providers they support. Reject requests where the action does not apply to the target, such as inspecting a secret with an EC2 inspection action.

## 3. Approval Replay Prevention

Bind each approval to the exact request, give it an expiration time, and make it single-use. Approval consumption must be atomic so concurrent requests cannot reuse one approval.

## 4. Object-Graph Disclosure Control

Authorization of the root object must not automatically authorize every connected object. Apply visibility and redaction decisions to each returned node, relationship, and sensitive field.

## 5. Administrative Endpoint Authorization

Protect policy, access-path, audit, feedback, and other administrative endpoints with explicit role or capability checks. Authentication alone is insufficient.

## 6. Credential Storage

Do not persist usable broker credentials as plaintext JSON. Store credentials in the broker, vault, or controlled executor and retain only opaque references and redacted metadata in the control plane.

## 7. Grant Lifetime Consistency

Ensure the real provider credential lifetime never exceeds the grant lifetime enforced by the control plane. Revocation and expiration behavior must remain consistent across both systems.

## 8. Controlled Runner Implementation

Replace the current in-process execution label with an actual controlled execution boundary. It should contain credentials, enforce timeouts and resource limits, isolate jobs, and return only approved outputs.

## 9. Typed Action Input Validation

Give every action a strict input schema with types, allowed values, length and size limits, and unknown-field rejection. Required-key checks alone are not sufficient.

## 10. Audit-Chain Concurrency

Serialize or otherwise coordinate audit appends so concurrent transactions cannot use the same previous hash and create competing chain heads.

## 11. Audit Durability and External Anchoring

The local hash chain detects modification but can be recomputed by a database administrator. Sign or periodically anchor chain heads in an independent, immutable trust domain.

## 12. Tenant Isolation

Add and enforce tenant scope for identities, graph nodes, graph edges, resources, approvals, grants, policy decisions, recommendations, and audit queries. Isolation must be enforced in persistence and service logic.

## 13. Policy Lifecycle Management

Add controlled workflows for proposing, validating, testing, activating, rolling back, and auditing policy versions. Policy changes must not become active through direct database edits.

## 14. Feedback Analyzer Accuracy

Normalize capability and observed API-call identifiers before comparing granted and exercised authority. Prevent naming differences from creating false least-privilege recommendations.

## 15. Operational Durability

Add database migrations, idempotency controls, retry policies, background-job handling, health checks, metrics, tracing, backup and restoration procedures, and documented recovery behavior.

## Implementation Rule

Address these as separate, reviewable work packages. Do not rewrite the full architecture to complete an individual item. Each change should preserve the existing request flow unless that item's accepted design explicitly requires otherwise.
