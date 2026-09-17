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
    (3, "003_phase_09_distributed_namespace_and_durability"),
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
    Uses PostgreSQL advisory lock to prevent migration races across multi-instance replicas.
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
        # Acquire PostgreSQL advisory lock (ID: 84729103) to serialize migrations across replicas
        has_advisory_lock = False
        if engine.dialect.name == "postgresql":
            try:
                conn.execute(text("SELECT pg_advisory_lock(84729103);"))
                conn.commit()
                has_advisory_lock = True
                # Re-check applied revisions inside lock to avoid race conditions
                applied = set(get_applied_revisions(engine))
            except Exception as lock_err:
                logger.warning(f"Could not acquire pg_advisory_lock: {lock_err}")

        try:
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
                elif version == 3:
                    # Non-destructive addition of namespace column to all durable security tables
                    inspector = inspect(conn)
                    namespace_tables = [
                        "sessions",
                        "security_events",
                        "policies",
                        "approvals",
                        "agents",
                        "delegations",
                        "executions",
                        "attack_scenarios",
                        "attack_runs",
                        "security_findings",
                        "security_alerts",
                    ]

                    for tbl in namespace_tables:
                        if tbl in inspector.get_table_names():
                            columns = [c["name"] for c in inspector.get_columns(tbl)]
                            if "namespace" not in columns:
                                logger.info(f"Adding namespace column to {tbl}...")
                                conn.execute(text(f"ALTER TABLE {tbl} ADD COLUMN namespace VARCHAR(128) NOT NULL DEFAULT 'default';"))
                            
                            # Add index for namespace queries
                            idx_name = f"idx_{tbl}_ns"
                            conn.execute(text(f"CREATE INDEX IF NOT EXISTS {idx_name} ON {tbl} (namespace);"))

                    # Add allowed_namespaces_json to api_keys if missing
                    if "api_keys" in inspector.get_table_names():
                        api_cols = [c["name"] for c in inspector.get_columns("api_keys")]
                        if "allowed_namespaces_json" not in api_cols:
                            conn.execute(text("ALTER TABLE api_keys ADD COLUMN allowed_namespaces_json JSON DEFAULT '[\"*\"]';"))

                    conn.commit()

                conn.execute(
                    text("INSERT INTO schema_migrations (version, name, applied_at) VALUES (:v, :n, :t);"),
                    {"v": version, "n": name, "t": utc_now()},
                )
                conn.commit()
                newly_applied += 1
                logger.info(f"Successfully applied migration {version}: '{name}'")

        finally:
            if has_advisory_lock:
                try:
                    conn.execute(text("SELECT pg_advisory_unlock(84729103);"))
                    conn.commit()
                except Exception as unlock_err:
                    logger.warning(f"Error releasing pg_advisory_unlock: {unlock_err}")

    return newly_applied