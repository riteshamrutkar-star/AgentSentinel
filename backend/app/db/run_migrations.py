"""
AgentSentinel Phase 0.9: Standalone Migration Runner CLI.
Used in deployment pipelines and multi-instance container orchestration
to run migrations once before application replicas start.
"""

import sys
from app.core.logger import logger
from app.db.session import engine
from app.db.migrations import apply_migrations

def main() -> int:
    logger.info("Initializing AgentSentinel migration runner...")
    try:
        newly_applied = apply_migrations(engine)
        logger.info(f"Migrations completed successfully. Applied {newly_applied} new revision(s).")
        return 0
    except Exception as e:
        logger.error(f"Migration execution failed: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main())
