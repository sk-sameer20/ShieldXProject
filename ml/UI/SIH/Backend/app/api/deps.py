"""
FastAPI Dependencies for ShieldX SOC API
"""
from typing import Generator
from sqlalchemy.orm import Session
from app.db.session import SyncSessionLocal


def get_db() -> Generator[Session, None, None]:
    """Dependency that provides a thread-local database session."""
    db = SyncSessionLocal()
    try:
        yield db
    finally:
        db.close()
