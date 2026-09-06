import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Settings:
    oidc_native_id_prefix: str = field(default_factory=lambda: os.environ.get("EDA_OIDC_NATIVE_ID_PREFIX", ""))
    oidc_directory_source: str = field(default_factory=lambda: os.environ.get("EDA_OIDC_DIRECTORY_SOURCE", ""))
    action_backend: str = field(default_factory=lambda: os.environ.get("EDA_ACTION_BACKEND", "mock"))
    aws_role_arn: str = field(default_factory=lambda: os.environ.get("EDA_AWS_ROLE_ARN", ""))
    aws_region: str = field(default_factory=lambda: os.environ.get("EDA_AWS_REGION", ""))
    runner_backend: str = field(default_factory=lambda: os.environ.get("EDA_RUNNER_BACKEND", "process"))
    runner_image: str = field(default_factory=lambda: os.environ.get("EDA_RUNNER_IMAGE", ""))
    environment: str = field(default_factory=lambda: os.environ.get("EDA_ENV", "dev"))

    def validate(self) -> None:
        """Reject unsafe/unknown configuration before startup has side effects."""
        if self.action_backend not in {"mock", "aws"}:
            raise ValueError("unknown action backend")
        if self.action_backend == "aws" and (not self.aws_role_arn or not self.aws_region):
            raise ValueError("AWS action backend requires role ARN and region")
        if self.runner_backend not in {"process", "docker"}:
            raise ValueError("unknown runner backend")
        if self.environment not in {"dev", "test", "production"}:
            raise ValueError("EDA_ENV must be dev, test, or production")
        if self.auth_mode not in {"dev", "oidc"}:
            raise ValueError("EDA_AUTH_MODE must be dev or oidc")
        if self.auth_mode == "oidc":
            from urllib.parse import urlsplit

            for name, value in (("EDA_OIDC_ISSUER", self.oidc_issuer),
                                ("EDA_OIDC_JWKS_URL", self.oidc_jwks_url)):
                parsed = urlsplit(value)
                if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
                    raise ValueError(f"{name} must be an HTTPS URL without credentials")
            if not self.oidc_audience.strip() or not self.oidc_provider_prefix.strip():
                raise ValueError("OIDC audience and provider prefix are required")
        for name in ("session_ttl_seconds", "grant_default_ttl_seconds", "approval_ttl_seconds",
                     "runner_timeout_seconds", "runner_max_output_bytes", "ingest_max_batch",
                     "source_max_age_seconds"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")
        if self.environment == "production":
            if self.auth_mode != "oidc":
                raise ValueError("production requires OIDC authentication")
            # Deliberate release gate, not a configurable bypass. Remove only
            # when real broker/actions, migrations and audit trust are qualified.
            raise ValueError("production is unavailable: broker/actions and durable trust are not qualified")

    @property
    def demo_enabled(self) -> bool:
        return self.environment in {"dev", "test"} and self.auth_mode == "dev"

    database_url: str = field(
        default_factory=lambda: os.environ.get("EDA_DATABASE_URL", "sqlite:///./eda.db")
    )
    token_secret: str = field(
        default_factory=lambda: os.environ.get("EDA_TOKEN_SECRET", "dev-only-secret-change-me")
    )
    session_ttl_seconds: int = field(
        default_factory=lambda: int(os.environ.get("EDA_SESSION_TTL", "3600"))
    )
    grant_default_ttl_seconds: int = field(
        default_factory=lambda: int(os.environ.get("EDA_GRANT_TTL", "900"))
    )

    # --- Identity front --------------------------------------------------
    # "dev": HMAC self-issued sessions (tests/local demos only).
    # "oidc": bearer tokens validated against the configured provider; the
    #         dev session endpoint is disabled and seeded identities are not
    #         honored.
    auth_mode: str = field(default_factory=lambda: os.environ.get("EDA_AUTH_MODE", "dev"))
    oidc_issuer: str = field(default_factory=lambda: os.environ.get("EDA_OIDC_ISSUER", ""))
    oidc_audience: str = field(default_factory=lambda: os.environ.get("EDA_OIDC_AUDIENCE", ""))
    oidc_jwks_url: str = field(default_factory=lambda: os.environ.get("EDA_OIDC_JWKS_URL", ""))
    # Canonical external-ID prefix for this provider, e.g. "okta" or "entra".
    oidc_provider_prefix: str = field(
        default_factory=lambda: os.environ.get("EDA_OIDC_PROVIDER_PREFIX", "oidc")
    )
    # Claim carrying the tenant (Entra: "tid"); or pin a static tenant for
    # single-tenant providers such as an Okta org.
    oidc_tenant_claim: str = field(
        default_factory=lambda: os.environ.get("EDA_OIDC_TENANT_CLAIM", "tid")
    )
    oidc_static_tenant: str = field(
        default_factory=lambda: os.environ.get("EDA_OIDC_STATIC_TENANT", "")
    )
    oidc_external_id_claim: str = field(default_factory=lambda: os.environ.get("EDA_OIDC_EXTERNAL_ID_CLAIM", "sub"))
    oidc_groups_claim: str = field(
        default_factory=lambda: os.environ.get("EDA_OIDC_GROUPS_CLAIM", "groups")
    )
    # amr values accepted as proof of MFA, and acr values likewise.
    oidc_mfa_amr: str = field(
        default_factory=lambda: os.environ.get("EDA_OIDC_MFA_AMR", "mfa")
    )
    oidc_mfa_acr: str = field(default_factory=lambda: os.environ.get("EDA_OIDC_MFA_ACR", ""))

    # --- Approvals ---------------------------------------------------------
    approval_ttl_seconds: int = field(
        default_factory=lambda: int(os.environ.get("EDA_APPROVAL_TTL", "3600"))
    )

    # --- Controlled runner ---------------------------------------------------
    runner_timeout_seconds: int = field(
        default_factory=lambda: int(os.environ.get("EDA_RUNNER_TIMEOUT", "30"))
    )
    runner_max_output_bytes: int = field(
        default_factory=lambda: int(os.environ.get("EDA_RUNNER_MAX_OUTPUT", str(256 * 1024)))
    )

    # --- Audit anchoring -------------------------------------------------------
    # Append-only file in an (ideally separate) trust domain receiving signed
    # chain heads. Production: object-lock storage / transparency log.
    audit_anchor_path: str = field(
        default_factory=lambda: os.environ.get("EDA_AUDIT_ANCHOR_PATH", "./audit_anchors.jsonl")
    )
    # Hex-encoded 32-byte Ed25519 seed. Empty = generated per process (anchors
    # then verify only within that process lifetime; configure for real use).
    audit_trusted_public_keys: str = field(default_factory=lambda: os.environ.get("EDA_AUDIT_TRUSTED_KEYS", ""))
    audit_anchor_max_age: int = field(default_factory=lambda: int(os.environ.get("EDA_AUDIT_ANCHOR_MAX_AGE", "3600")))
    audit_anchor_min_seq: int = field(default_factory=lambda: int(os.environ.get("EDA_AUDIT_ANCHOR_MIN_SEQ", "1")))
    audit_anchor_key: str = field(
        default_factory=lambda: os.environ.get("EDA_AUDIT_ANCHOR_KEY", "")
    )

    # --- Relationship ingestion ------------------------------------------
    ingest_max_batch: int = field(
        default_factory=lambda: int(os.environ.get("EDA_INGEST_MAX_BATCH", "1000"))
    )
    # A source that has not synced within this window is stale: identities it
    # asserted stop resolving (fail closed) until it syncs again.
    source_max_age_seconds: int = field(
        default_factory=lambda: int(os.environ.get("EDA_SOURCE_MAX_AGE", str(7 * 86400)))
    )


settings = Settings()
