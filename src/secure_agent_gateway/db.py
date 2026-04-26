from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import StaticPool

from secure_agent_gateway.config import get_settings


class Base(DeclarativeBase):
    pass


def build_engine():
    settings = get_settings()
    if settings.database_url.endswith(":memory:"):
        return create_engine(
            settings.database_url,
            future=True,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
    if settings.database_url.startswith("sqlite:///./"):
        relative_path = settings.database_url.removeprefix("sqlite:///./")
        Path(relative_path).parent.mkdir(parents=True, exist_ok=True)
    if settings.database_url.startswith("sqlite"):
        return create_engine(
            settings.database_url,
            future=True,
            connect_args={"check_same_thread": False},
        )
    return create_engine(settings.database_url, future=True)


engine = build_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def init_db() -> None:
    from secure_agent_gateway import models  # noqa: F401

    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
