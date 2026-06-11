import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Settings:
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
    oidc_groups_claim: str = field(
        default_factory=lambda: os.environ.get("EDA_OIDC_GROUPS_CLAIM", "groups")
    )
    # amr values accepted as proof of MFA, and acr values likewise.
    oidc_mfa_amr: str = field(
        default_factory=lambda: os.environ.get("EDA_OIDC_MFA_AMR", "mfa,otp,hwk,swk")
    )
    oidc_mfa_acr: str = field(default_factory=lambda: os.environ.get("EDA_OIDC_MFA_ACR", ""))

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
