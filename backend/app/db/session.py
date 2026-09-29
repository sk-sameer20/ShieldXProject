"""
SQLAlchemy 2.0 Engine & Session Management for ShieldX SOC
Supports both Async (for FastAPI endpoints) and Sync (for scripts/migrations).
"""
import os
from typing import AsyncGenerator
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import Session, sessionmaker

# Database paths & connection strings
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_DB_FILE = os.path.join(BASE_DIR, "shieldx.db")

SYNC_DATABASE_URL = os.getenv("SHIELDX_SYNC_DB_URL", f"sqlite:///{DEFAULT_DB_FILE}")
ASYNC_DATABASE_URL = os.getenv("SHIELDX_ASYNC_DB_URL", f"sqlite+aiosqlite:///{DEFAULT_DB_FILE}")

# ─── SQLite PRAGMA Configuration (WAL mode, Foreign Keys) ───
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA foreign_keys=ON;")
    cursor.execute("PRAGMA synchronous=NORMAL;")
    cursor.close()

# ─── Synchronous Engine & Session (Used by seed scripts & migration tools) ───
sync_engine = create_engine(
    SYNC_DATABASE_URL,
    echo=False,
    future=True,
    connect_args={"check_same_thread": False},
)

SyncSessionLocal = sessionmaker(
    bind=sync_engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)

def get_sync_session() -> Session:
    """Yield a synchronous database session."""
    session = SyncSessionLocal()
    try:
        return session
    finally:
        pass

# ─── Asynchronous Engine & Session (Used by FastAPI async endpoints) ───
async_engine = create_async_engine(
    ASYNC_DATABASE_URL,
    echo=False,
    future=True,
    connect_args={"check_same_thread": False},
)

AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)

async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency for yielding scoped async database sessions."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
