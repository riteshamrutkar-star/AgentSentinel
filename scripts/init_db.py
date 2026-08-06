#!/usr/bin/env python3
"""
AgentSentinel - Database Initialization & Verification Script (Phase 3B)
Creates tables, populates initial policy rules, inserts sample security events, and verifies PostgreSQL retrieval.
"""

import os
import sys
from sqlalchemy import inspect

# Ensure backend folder is on python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.db.base import Base
from app.db.session import engine, SessionLocal
from app.db.models import SessionModel, EventModel, PolicyModel
from app.db.crud import save_security_event, get_security_event_by_id, list_security_events, create_policy
from app.events.examples import get_benign_event_example, get_suspicious_event_example

def init_and_test_db():
    print("=" * 80)
    print("AGENTSENTINEL PHASE 3B: POSTGRESQL & ORM PERSISTENCE VERIFICATION")
    print("=" * 80)

    # 1. Verify Active SQLAlchemy Dialect
    dialect_name = engine.dialect.name
    print(f"\n[1] Verifying Active Database Backend...")
    print(f"    Active Dialect: {dialect_name.upper()}")
    assert dialect_name == "postgresql", f"EXPECTED POSTGRESQL DIALECT, BUT GOT '{dialect_name}'!"
    print("    [PASS] Confirmed PostgreSQL database engine is active!")

    # 2. Schema Table Initialization
    print("\n[2] Creating Database Schema Tables...")
    Base.metadata.create_all(bind=engine)

    inspector = inspect(engine)
    existing_tables = inspector.get_table_names()
    print(f"    Tables found in PostgreSQL: {', '.join(existing_tables)}")
    expected_tables = ["sessions", "security_events", "policies", "approvals", "detector_models"]
    for tbl in expected_tables:
        assert tbl in existing_tables, f"Missing table '{tbl}' in PostgreSQL!"
    print("    [PASS] All 5 core tables exist in PostgreSQL!")

    db = SessionLocal()
    try:
        # 3. Seed Default Policies (Idempotent)
        existing_policies = db.query(PolicyModel).count()
        print(f"\n[3] Seeding Security Policy Rules (Existing: {existing_policies})...")
        if existing_policies == 0:
            create_policy(
                db,
                policy_name="Allow Read-Only Web Search",
                effect="ALLOW",
                role="*",
                tool_name="google_search",
                action_type="NETWORK",
                resource_pattern="*",
                description="Default permission for search queries",
                priority=10,
            )
            create_policy(
                db,
                policy_name="Block Privileged Credential Files",
                effect="DENY",
                role="*",
                tool_name="read_system_file",
                action_type="READ",
                resource_pattern="*/.ssh/*",
                description="Prohibits reading SSH keys or private credentials",
                priority=1,
            )
            print("    [PASS] Default security policies seeded.")
        else:
            print("    [PASS] Security policies already exist.")

        # 4. Insert Sample Events (Idempotent check)
        print("\n[4] Inserting & Verifying Phase 3A Security Events...")
        benign_event = get_benign_event_example()
        suspicious_event = get_suspicious_event_example()

        # Check if already present
        if not get_security_event_by_id(db, benign_event.identity.event_id):
            saved_benign = save_security_event(db, benign_event)
            print(f"    Saved Benign Event ID: {saved_benign.event_id} (Session: {saved_benign.session_id})")
        else:
            print(f"    Benign Event ID {benign_event.identity.event_id} already present in DB.")

        if not get_security_event_by_id(db, suspicious_event.identity.event_id):
            saved_suspicious = save_security_event(db, suspicious_event)
            print(f"    Saved Suspicious Event ID: {saved_suspicious.event_id} (Session: {saved_suspicious.session_id})")
        else:
            print(f"    Suspicious Event ID {suspicious_event.identity.event_id} already present in DB.")

        # 5. Query Back & Field Integrity Check
        print("\n[5] End-to-End Verification of Event Retrieval from PostgreSQL...")
        queried = get_security_event_by_id(db, suspicious_event.identity.event_id)
        assert queried is not None, "Failed to retrieve event from PostgreSQL!"

        print(f"    - Event ID: {queried.event_id}")
        print(f"    - Agent ID: {queried.agent_id}")
        print(f"    - Tool Name: {queried.tool_name}")
        print(f"    - Threat Flags: {queried.threat_flags_json}")
        print(f"    - Anomaly Score: {queried.anomaly_score}")
        print(f"    - Policy Decision: {queried.decision_result}")
        print(f"    - Execution Allowed: {queried.execution_allowed}")
        print(f"    - Raw Payload Survives: {'identity' in queried.raw_payload_json}")
        print(f"    - Session Relationship: {queried.session.session_id}")

        assert queried.agent_id == "agent_coder_bot", "Agent ID mismatch!"
        assert queried.decision_result == "DENY", "Policy decision mismatch!"
        assert queried.execution_allowed == False, "Execution allowed mismatch!"
        assert queried.session is not None, "Session relationship failed!"

        all_events = list_security_events(db, limit=10)
        print(f"\n    [PASS] Total Security Events in PostgreSQL: {len(all_events)}")

        print("=" * 80)
        print("[SUCCESS] AGENTSENTINEL PHASE 3B POSTGRESQL VERIFICATION SUCCESSFUL")
        print("=" * 80)

    finally:
        db.close()

if __name__ == "__main__":
    init_and_test_db()
