"""
Enkstein — Sync database compatibility layer
Re-exports Base from app.core.database so all models share a single metadata
registry, then provides a standard sync engine + session for routes that use
Depends(get_db) with a plain sqlalchemy.orm.Session.

Usage in models:
    from app.database import Base

Usage in sync routes:
    from app.database import get_db
    from sqlalchemy.orm import Session
    def my_route(db: Session = Depends(get_db)):
        ...

Usage in seed scripts:
    from app.database import SessionLocal, engine, Base
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from typing import Generator

from app.core.config import settings

# ── Shared declarative base (same metadata as async engine) ──────────────────
# All models that import Base from here use the SAME MetaData object, so
# app.core.database.Base.metadata.create_all() picks up every table.
from app.core.database import Base  # noqa: F401  re-export

# ── Sync engine (uses psycopg2 / pg8000 driver) ───────────────────────────────
engine = create_engine(
    settings.DATABASE_URL_SYNC,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
)

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency — yields a sync SQLAlchemy session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
