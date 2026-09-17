"""
AgentSentinel Phase 0.8: Non-Destructive Database Migration Engine.
Applies schema revisions deterministically, tracks history in schema_migrations,
and preserves all historical security data, research datasets, and observations.
"""

from datetime import datetime, timezone
from typing import List, Tuple
from sqlalchemy import text, inspect
from sqlalchemy.engine import Engine
from app.core.logger import logger
from app.db.base import Base

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

REVISIONS: List[Tuple[int, str]] = [
    (1, "001_initial_core_schema"),
    (2, "002_phase_08_production_hardening"),
]

def ensure_migration_table(engine: Engine) -> None:
    """Ensures schema_migrations table exists."""
    with engine.connect() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name VARCHAR(128) NOT NULL,
                applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        """))
        conn.commit()

def get_applied_revisions(engine: Engine) -> List[int]:
    """Returns list of already applied revision numbers."""
    ensure_migration_table(engine)
    with engine.connect() as conn:
        result = conn.execute(text("SELECT version FROM schema_migrations ORDER BY version ASC;"))
        return [row[0] for row in result.fetchall()]

def apply_migrations(engine: Engine) -> int:
    """
    Applies any unapplied schema revisions non-destructively.
    Returns count of newly applied migrations.
    """
    ensure_migration_table(engine)
    applied = set(get_applied_revisions(engine))
    newly_applied = 0

    # Ensure all tables defined in Base.metadata exist without dropping
    try:
        Base.metadata.create_all(bind=engine)
    except Exception as e:
        logger.warning(f"Metadata create_all notice: {e}")

    with engine.connect() as conn:
        for version, name in REVISIONS:
            if version in applied:
                continue

            logger.info(f"Applying database migration {version}: '{name}'...")
            
            if version == 1:
                # Core schema revision marker
                pass
            elif version == 2:
                # Add operational indexes if PostgreSQL
                if engine.dialect.name == "postgresql":
                    conn.execute(text("""
                        CREATE INDEX IF NOT EXISTS idx_security_events_time ON security_events (timestamp DESC);
                        CREATE INDEX IF NOT EXISTS idx_security_events_tool ON security_events (tool_name);
                        CREATE INDEX IF NOT EXISTS idx_security_alerts_status ON security_alerts (status);
                        CREATE INDEX IF NOT EXISTS idx_security_alerts_severity ON security_alerts (severity);
                        CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys (key_hash);
                    """))

            conn.execute(
                text("INSERT INTO schema_migrations (version, name, applied_at) VALUES (:v, :n, :t);"),
                {"v": version, "n": name, "t": utc_now()},
            )
            conn.commit()
            newly_applied += 1
            logger.info(f"Successfully applied migration {version}: '{name}'")

    return newly_applied