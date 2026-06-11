from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import settings


class Base(DeclarativeBase):
    pass


def make_engine(database_url: str | None = None):
    url = database_url or settings.database_url
    kwargs = {}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    return create_engine(url, **kwargs)


engine = make_engine()
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def init_db(target_engine=None) -> None:
    """Create all tables. Reference implementation only - production would use migrations."""
    from . import models  # noqa: F401  (register tables on Base)

    Base.metadata.create_all(target_engine or engine)


def get_session():
    """FastAPI dependency yielding a DB session."""
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()
