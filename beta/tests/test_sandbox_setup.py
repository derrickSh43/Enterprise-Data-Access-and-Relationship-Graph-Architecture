from pathlib import Path
import importlib.util
from datetime import datetime, timezone
from dataclasses import replace
import pytest
from sqlalchemy import select
from eda.connectors.fixture import FixtureConnector
from eda.connectors.contracts import ObjectRecord, Reference
from eda.models import ConnectorFact, AccessNode
from eda import identity_providers
from eda.config import Settings
from test_foundation import ingest_okta_user, oidc_session

path = Path(__file__).resolve().parents[2] / "sandbox" / "sync.py"
spec = importlib.util.spec_from_file_location("sandbox_sync", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

def test_operator_snapshot_rollback_and_empty_reconciliation(db):
    obj = ObjectRecord(ref=Reference(source_id="sandbox-test", native_id="test:1", kind="user"),
                       display_name="Test", observed_at=datetime.now(timezone.utc))
    def run(connector):
        return module.import_source(db, connector, "acme", "sandbox-test", "fixture", "test:")
    assert run(FixtureConnector([([obj], [])])) == 1
    db.commit()
    class Broken(FixtureConnector):
        def snapshot(self):
            yield [], []
            raise RuntimeError("network interrupted")
    with pytest.raises(RuntimeError):
        run(Broken([]))
    db.rollback()
    assert len(db.scalars(select(ConnectorFact).where(ConnectorFact.source_id == "sandbox-test", ConnectorFact.generation == "live")).all()) == 1
    assert run(FixtureConnector([])) == 0
    db.commit()

def test_operator_source_rebinding_refused(db):
    module.import_source(db, FixtureConnector([]), "acme", "sandbox-test", "fixture", "test:")
    with pytest.raises(ValueError, match="configuration differs"):
        module.import_source(db, FixtureConnector([]), "foreign", "sandbox-test", "fixture", "test:")

def test_pinned_directory_can_preserve_connector_native_prefix(db, monkeypatch):
    session = oidc_session()
    source = ingest_okta_user(db)
    monkeypatch.setattr(identity_providers, "settings", replace(Settings(), oidc_directory_source=source.id,
        oidc_issuer=session.issuer, oidc_provider_prefix="okta", oidc_native_id_prefix="okta:"))
    assert identity_providers.map_principal(db, session).external_id == "okta:00u123"


def test_configuration_writer_preserves_existing_secrets(tmp_path, monkeypatch, capsys):
    config_path = Path(__file__).resolve().parents[2] / "sandbox" / "configure.py"
    spec = importlib.util.spec_from_file_location("sandbox_config", config_path)
    config = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(config)
    monkeypatch.setattr(config, "ROOT", tmp_path)
    def output(folder, name):
        if name == "collector_client_secret":
            return "secret-fixture-$123"
        return {"ENTRA_TENANT_ID": "tenant"} if folder == "entra" else {"AWS_REGION": "us-east-1"}
    monkeypatch.setattr(config, "output", output)
    config.main()
    original = (tmp_path / ".env").read_text()
    assert "ENTRA_COLLECTOR_CLIENT_SECRET='secret-fixture-$123'" in original
    assert "secret-fixture" not in capsys.readouterr().out
    with pytest.raises(FileExistsError):
        config.main()
    assert (tmp_path / ".env").read_text() == original
