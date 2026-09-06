# Deployment options and limits

For the supported small connected sandbox, follow [INSTALL.md](../INSTALL.md). It uses sandbox/entra, sandbox/aws and sandbox/compose.yaml. The Dockerfile is deploy/Dockerfile.

## Local-only demo

`docker compose -f deploy/compose.yaml up --build` runs a separate local demo with development authentication and mock actions. It needs no Entra or AWS setup and must remain bound to localhost. Its credentials and identities are demonstration-only. Do not confuse it with the OIDC-connected sandbox.

## Broader cloud foundation

infra/bootstrap and infra/platform are separate, incomplete building blocks. They provision protected state storage, private managed PostgreSQL, KMS, audit retention, queues, registry, cluster and IAM foundations in an existing VPC. They do not deploy complete ECS application services, database runtime-user provisioning, distributed workers, egress, independent audit administration or a release/restore pipeline.

The audit bucket in that foundation uses compliance retention and prevent_destroy protections. It is not suitable for casual disposable tests without a separate retention/decommissioning plan. No production deployment is claimed; production application startup remains blocked. Do not apply this module as the small sandbox.

## Kubernetes

A local Kubernetes layout has been discussed, but manifests and Helm packaging are not implemented.

## Isolated runner

EDA_RUNNER_BACKEND=docker requires a digest-pinned EDA_RUNNER_IMAGE. This runner has no host mounts or network; it is intended for offline handlers. Choosing it does not enable networked cloud actions or establish qualified isolation. It is separate from running EDA itself in Docker Compose.
