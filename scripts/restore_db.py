"""
AgentSentinel Phase 0.8: Database Restore CLI Tool.
Restores database state from a validated backup file with checksum verification.
"""

import argparse
import hashlib
import json
import os
import sys
from sqlalchemy import text

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from sqlalchemy import create_engine, inspect, text

from app.core.config import settings
from app.db.session import engine as default_engine
from app.db.models import Base
from app.db.migrations import apply_migrations


def compute_file_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def restore_database(
    backup_path: str,
    verify_only: bool = False,
    target_db: str = None,
    target_url: str = None,
) -> bool:
    if not os.path.exists(backup_path):
        print(f"[ERROR] Backup file not found: {backup_path}")
        return False

    meta_path = f"{backup_path}.meta"
    actual_hash = compute_file_sha256(backup_path)

    if os.path.exists(meta_path):
        with open(meta_path, "r", encoding="utf-8") as mf:
            meta = json.load(mf)
        expected_hash = meta.get("sha256")
        if expected_hash and actual_hash != expected_hash:
            print(f"[ERROR] Checksum verification failed! File may be corrupted.")
            print(f"  Expected: {expected_hash}")
            print(f"  Actual  : {actual_hash}")
            return False
        print(f"[OK] SHA-256 Checksum verified: {actual_hash}")
    else:
        print(f"[WARN] No metadata sidecar found; proceeding with hash {actual_hash[:16]}...")

    with open(backup_path, "r", encoding="utf-8") as f:
        backup_data = json.load(f)

    tables_data = backup_data.get("tables", {})
    print(f"[*] Backup contains {len(tables_data)} tables. Verify only = {verify_only}")

    for tname, rows in tables_data.items():
        print(f"    - '{tname}': {len(rows)} records")

    if verify_only:
        print("[SUCCESS] Backup file verified successfully.")
        return True

    # Resolve target engine
    if target_url:
        dest_engine = create_engine(target_url)
        dest_db_name = target_url.split("/")[-1].split("?")[0]
    elif target_db:
        base_url = settings.sync_database_url
        dest_url = base_url.rsplit("/", 1)[0] + f"/{target_db}"
        dest_engine = create_engine(dest_url)
        dest_db_name = target_db
    else:
        dest_engine = default_engine
        dest_db_name = settings.POSTGRES_DB

    print(f"[*] Initializing schema on target database '{dest_db_name}'...")
    Base.metadata.create_all(bind=dest_engine)
    apply_migrations(dest_engine)

    # Topological restore order respecting foreign keys
    dependency_order = [
        "policies",
        "detector_models",
        "sessions",
        "agents",
        "schema_migrations",
        "api_keys",
        "security_alerts",
        "attack_scenarios",
        "research_datasets",
        "research_experiments",
        "delegations",
        "security_events",
        "approvals",
        "executions",
        "attack_runs",
        "security_findings",
        "research_runs",
        "research_observations",
    ]
    # Add any extra tables that might be in backup
    all_table_names = list(tables_data.keys())
    ordered_tables = [t for t in dependency_order if t in all_table_names]
    for t in all_table_names:
        if t not in ordered_tables:
            ordered_tables.append(t)

    print(f"[*] Restoring records into database '{dest_db_name}'...")
    total_restored = 0
    inspector = inspect(dest_engine)
    table_json_columns = {}
    for tname in ordered_tables:
        table_json_columns[tname] = set()
        try:
            for col in inspector.get_columns(tname):
                col_type_str = str(col.get("type", "")).upper()
                if "JSON" in col_type_str:
                    table_json_columns[tname].add(col["name"])
        except Exception:
            pass

    with dest_engine.connect() as conn:
        try:
            conn.execute(text("SET session_replication_role = 'replica';"))
            conn.commit()
        except Exception:
            pass

        for tname in ordered_tables:
            rows = tables_data.get(tname, [])
            if not rows:
                print(f"    - Table '{tname}': 0 records to restore")
                continue

            json_cols = table_json_columns.get(tname, set())
            table_restored = 0
            first_error = None
            for r in rows:
                clean_r = {}
                for k, v in r.items():
                    if k in json_cols or isinstance(v, (dict, list)):
                        if v is None:
                            clean_r[k] = None
                        elif isinstance(v, (dict, list)):
                            clean_r[k] = json.dumps(v)
                        elif isinstance(v, str):
                            try:
                                json.loads(v)
                                clean_r[k] = v
                            except Exception:
                                clean_r[k] = json.dumps(v)
                        else:
                            clean_r[k] = json.dumps(v)
                    else:
                        clean_r[k] = v

                cols = list(clean_r.keys())
                col_names = ", ".join(f'"{c}"' for c in cols)
                param_names = ", ".join(f":{c}" for c in cols)
                stmt = text(f'INSERT INTO "{tname}" ({col_names}) VALUES ({param_names}) ON CONFLICT DO NOTHING;')
                try:
                    conn.execute(stmt, clean_r)
                    table_restored += 1
                except Exception as e:
                    if first_error is None:
                        first_error = str(e)

            conn.commit()
            total_restored += table_restored
            err_msg = f" (Warning: first error: {first_error[:80]}...)" if first_error else ""
            print(f"    - Restored {table_restored}/{len(rows)} records to '{tname}'{err_msg}")

        try:
            conn.execute(text("SET session_replication_role = 'origin';"))
            conn.commit()
        except Exception:
            pass

    print(f"[SUCCESS] Database restore completed successfully into '{dest_db_name}'. Total records inserted: {total_restored}")
    return True


def main():
    parser = argparse.ArgumentParser(description="AgentSentinel Database Restore Tool")
    parser.add_argument("backup_file", help="Path to backup JSON file")
    parser.add_argument("--verify-only", action="store_true", help="Validate integrity without restoring")
    parser.add_argument("--target-db", default=None, help="Name of isolated target database")
    parser.add_argument("--target-url", default=None, help="Full connection URL for target database")
    args = parser.parse_args()
    success = restore_database(
        args.backup_file,
        verify_only=args.verify_only,
        target_db=args.target_db,
        target_url=args.target_url,
    )
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()