"""
Database Session Management — Async + Sync SQLAlchemy Engines & Sessions.

- Async engine / session: for FastAPI route handlers (async).
- Sync engine / session: for Celery workers and background tasks (sync).

Both share the same DATABASE_URL but require different drivers:
- async: asyncpg (postgresql+asyncpg://...)
- sync : psycopg2 (postgresql://... or postgresql+psycopg2://...)
"""

from collections.abc import AsyncGenerator, Generator

from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings

# ============================================================
# Async Engine & Session (FastAPI)
# ============================================================
engine = create_async_engine(
    settings.DATABASE_URL,
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
    echo=settings.DEBUG,
    future=True,
)

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# ============================================================
# Sync Engine & Session (Celery / background workers)
# ============================================================
def _to_sync_url(url: str) -> str:
    """
    Convert an async SQLAlchemy URL to a sync one.

    - postgresql+asyncpg://...  -> postgresql+psycopg2://...
    - sqlite+aiosqlite:///...   -> sqlite:///...
    - Anything else: return as-is (assumed already sync).
    """
    if "+asyncpg" in url:
        return url.replace("+asyncpg", "+psycopg2")
    if "+aiosqlite" in url:
        return url.replace("+aiosqlite", "")
    return url


_sync_url = _to_sync_url(settings.DATABASE_URL)

sync_engine = create_engine(
    _sync_url,
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
    echo=settings.DEBUG,
    future=True,
)

SessionLocal = sessionmaker(
    bind=sync_engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


# ============================================================
# Base Model
# ============================================================
class Base(DeclarativeBase):
    """Declarative base for all SQLAlchemy models."""
    pass


# ============================================================
# FastAPI Dependency: get_db (async)
# ============================================================
async def get_db() -> AsyncGenerator[AsyncSession, None]:  # noqa: UP043
    """
    FastAPI dependency that yields an async database session.
    Automatically commits on success and rolls back on exception.
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ============================================================
# Celery / Background Dependency: get_sync_db
# ============================================================
def get_sync_db() -> Generator[Session, None, None]:
    """
    Yield a sync SQLAlchemy session for Celery workers and
    background tasks. Commits on success, rolls back on exception.
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# ============================================================
# Database Initialization (dev only)
# ============================================================
async def init_db() -> None:
    """
    Database initialization — DEPRECATED.

    In production, use Alembic migrations: `alembic upgrade head`
    This function only creates tables in development mode when explicitly needed.
    """
    if settings.DEBUG:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
