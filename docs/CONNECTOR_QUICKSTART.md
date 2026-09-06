# Connector registration and delivery

This workflow is implemented and locally tested. Entra Graph and cloud execution remain unverified against live environments. It requires an existing administrator capability; production identity/bootstrap provisioning is still a release prerequisite.

1. An administrator calls POST /relationship-sources with source_id, provider, and allowed_namespace. The tenant comes from the authenticated administrator. Save the returned collector_token in your secret manager: it is returned once, never recorded in audit, and stored only as a hash. The bundled Entra collector uses the namespace entra:. Use an empty namespace only for a connector whose entire native-ID namespace belongs to that source.
2. The administrator calls POST /relationship-sources/{source_id}/manifest with the connector's describe() document. The collector token cannot approve its own assertion permissions. Review foreign source references and permission_semantics before registration.
3. The collector calls GET /relationship-sources/{source_id}/sync-state with its source token. Initial sequence is zero. If a snapshot is active after interruption, replay any unacknowledged identical message before deciding whether to abort. A server sequence alone does not prove that a different local payload was accepted.
4. Install ./beta[sdk,entra] and use the SDK below. Persist each envelope before sending, and persist its matching acknowledgement before advancing. A durable spool is not supplied yet; do not run unattended collectors without one.

```python
from eda.connectors import collect_snapshot
from eda.connectors.client import SyncClient

# connector: configured Connector implementation, e.g. EntraConnector.
# token comes from a secret manager, never source code or command-line arguments.
with SyncClient("https://eda.example", source_id, token) as client:
    for message in collect_snapshot(connector, first_sequence=last_acknowledged + 1):
        durable_store.save_pending(message.model_dump(mode="json"))
        receipt = client.send(message)
        durable_store.record_acknowledgement(receipt)
```

`durable_store` above is an integration requirement, not a bundled class. The client retries transport failures and selected transient HTTP responses at most four times using the same bytes. It rejects redirects, mismatched receipts and oversized responses. Errors do not include provider response bodies. A collection error never emits a complete event; retain or explicitly abort its staged snapshot before starting another one.

For Microsoft Entra sign-in, configure a tenant-specific OIDC issuer/audience, EDA_OIDC_EXTERNAL_ID_CLAIM=oid, EDA_OIDC_PROVIDER_PREFIX=entra, EDA_OIDC_NATIVE_ID_PREFIX=entra:, and EDA_OIDC_DIRECTORY_SOURCE to the registered source ID. Keep the application tenant mapping consistent with the source tenant. This binding connects a verified identity to its imported user; membership alone does not establish AWS roles or PostgreSQL grants.

Versioned contracts are in contracts/v1. Python authoring is available in eda.connectors; other languages can implement the same HTTP/JSON contract. A separately published standalone SDK package and automatic connector orchestration remain outstanding.
