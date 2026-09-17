from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from app.core.config import settings
from app.core.logger import logger

def create_app_engine():
    """
    Creates the SQLAlchemy database engine with bounded connection pooling.
    Configured for production connection safety and resilient retry.
    """
    database_url = settings.sync_database_url

    engine_kwargs = {"pool_pre_ping": True}
    if not database_url.startswith("sqlite"):
        engine_kwargs.update({
            "pool_size": settings.DB_POOL_SIZE,
            "max_overflow": settings.DB_MAX_OVERFLOW,
            "pool_timeout": settings.DB_POOL_TIMEOUT,
            "pool_recycle": settings.DB_POOL_RECYCLE,
        })

    try:
        engine = create_engine(database_url, **engine_kwargs)
        # Test connection immediately on initialization
        with engine.connect() as conn:
            pass
        logger.info(f"Successfully connected to database at {settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}")
        return engine
    except Exception as e:
        logger.warning(f"Database connection attempt on startup: {e}. Proceeding with lazy connection pool.")
        # Create resilient engine that will reconnect on request
        return create_engine(database_url, **engine_kwargs)

engine = create_app_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
