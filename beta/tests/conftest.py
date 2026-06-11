import os

# Must be set before any eda import: eda.db builds its engine from this at import time.
os.environ["EDA_DATABASE_URL"] = "sqlite:///./test_eda.db"
os.environ["EDA_AUTH_MODE"] = "dev"  # dev sessions are test/demo-only by design

import pytest  # noqa: E402

from eda.db import Base, SessionLocal, engine, init_db  # noqa: E402
from eda.seed import seed  # noqa: E402


@pytest.fixture()
def db():
    Base.metadata.drop_all(engine)
    init_db()
    session = SessionLocal()
    seed(session)
    yield session
    session.close()


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient

    from eda.api import app

    Base.metadata.drop_all(engine)
    with TestClient(app) as test_client:  # lifespan runs init_db + seed
        yield test_client
