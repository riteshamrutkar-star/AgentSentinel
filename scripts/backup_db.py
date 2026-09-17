"""
AgentSentinel Phase 0.8: Database Backup CLI Tool.
Creates timestamped, checksummed database snapshots of all security events,
policies, agent delegations, research datasets, observations, and audit tables.
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from sqlalchemy import inspect, text

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.core.config import settings
from app.db.session import engine


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def compute_file_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def backup_database(output_dir: str = "backups") -> str:
    os.makedirs(output_dir, exist_ok=True)
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_filename = f"agentsentinel_backup_{timestamp_str}.json"
    backup_path = os.path.join(output_dir, backup_filename)

    inspector = inspect(engine)
    table_names = inspector.get_table_names()

    backup_payload = {
        "metadata": {
            "application": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "environment": settings.ENVIRONMENT,
            "created_at": utc_now(),
            "tables_count": len(table_names),
        },
        "tables": {},
    }

    print(f"[*] Starting backup of {len(table_names)} tables from '{settings.POSTGRES_DB}'...")

    with engine.connect() as conn:
        for tname in table_names:
            res = conn.execute(text(f'SELECT * FROM "{tname}";'))
            columns = list(res.keys())
            rows = [dict(zip(columns, [str(v) if isinstance(v, (datetime,)) else v for v in row])) for row in res.fetchall()]
            backup_payload["tables"][tname] = rows
            print(f"    - Table '{tname}': {len(rows)} records exported")

    with open(backup_path, "w", encoding="utf-8") as f:
        json.dump(backup_payload, f, indent=2, default=str)

    sha256 = compute_file_sha256(backup_path)
    meta_path = f"{backup_path}.meta"
    with open(meta_path, "w", encoding="utf-8") as mf:
        json.dump({"filename": backup_filename, "sha256": sha256, "created_at": utc_now()}, mf, indent=2)

    print(f"[SUCCESS] Database backup saved to: {backup_path}")
    print(f"          SHA-256 Digest: {sha256}")
    return backup_path


def main():
    parser = argparse.ArgumentParser(description="AgentSentinel Database Backup Tool")
    parser.add_argument("--output-dir", default="backups", help="Target backup directory")
    args = parser.parse_args()
    backup_database(args.output_dir)


if __name__ == "__main__":
    main()