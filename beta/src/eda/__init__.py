"""Local-first governed enterprise control plane (reference implementation).

Components:
    identity      - session issuance/verification (HMAC tokens; swap for OIDC/SAML)
    access_graph  - authority relationships and access-path resolution
    policy        - deterministic, versioned policy evaluation
    broker        - temporary scoped authority (mock STS locally, AWS STS adapter)
    objects       - object/ontology graph, returns context only after authority
    actions       - controlled verbs with risk, rollback, and blast-radius metadata
    audit         - append-only hash-chained evidence log
    feedback      - local analytics over audit data -> human-gated recommendations
    gateway       - orchestrates the full request flow
"""

__version__ = "0.1.0"
