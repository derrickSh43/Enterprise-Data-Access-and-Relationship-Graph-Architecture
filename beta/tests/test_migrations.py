from pathlib import Path
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


def test_baseline_to_connector_upgrade_preserves_data(tmp_path, monkeypatch):
    url = "sqlite:///" + (tmp_path / "migration.db").as_posix()
    monkeypatch.setenv("EDA_DATABASE_URL", url)
    config = Config(str(Path(__file__).parents[1] / "alembic.ini"))
    command.upgrade(config, "0001")
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO access_nodes (id,kind,name,attrs) VALUES ('saved','user','saved','{}')"))
    command.upgrade(config, "head")
    assert "connector_receipts" in inspect(engine).get_table_names()
    with engine.connect() as conn:
        assert conn.scalar(text("SELECT name FROM access_nodes WHERE id='saved'")) == "saved"
    command.check(config)
    command.downgrade(config, "0001")
    assert "connector_receipts" not in inspect(engine).get_table_names()
    engine.dispose()
