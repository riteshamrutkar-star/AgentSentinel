from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from app.core.config import settings
from app.core.logger import logger

def create_app_engine():
    """
    Creates the SQLAlchemy database engine for PostgreSQL.
    Strictly connects to PostgreSQL and raises an error if unreachable.
    """
    database_url = settings.sync_database_url

    try:
        engine = create_engine(database_url, pool_pre_ping=True)
        # Test connection immediately on initialization
        with engine.connect() as conn:
            pass
        logger.info(f"Successfully connected to PostgreSQL at {settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}")
        return engine
    except Exception as e:
        logger.error(f"Failed to connect to PostgreSQL database: {e}")
        raise RuntimeError(f"Database Connection Failed: Unable to connect to PostgreSQL. Error: {e}") from e

engine = create_app_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
