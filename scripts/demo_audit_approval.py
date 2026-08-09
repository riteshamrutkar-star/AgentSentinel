#!/usr/bin/env python3
"""
AgentSentinel Phase 6 - Audit Logging & Human Approval Workflow Demonstration Script
Demonstrates runtime interception of risky actions, automatic approval request creation,
human approval/rejection decisioning, PostgreSQL state persistence, and audit trail queries.
"""

import os
import sys

# Ensure backend folder is on python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.audit.repository import get_approval_by_event_id, list_approvals, list_audit_events
from app.audit.service import approve_action, reject_action
from app.db.crud import get_security_event_by_id
from app.db.session import SessionLocal
from app.interceptor.proxy import intercept_tool_call
from app.interceptor.schema import ToolCallRequest

def run_audit_approval_demo():
    print("=" * 80)
    print("AGENTSENTINEL PHASE 6: AUDIT LOGGING & HUMAN APPROVAL WORKFLOW DEMO")
    print("=" * 80)

    db = SessionLocal()
    try:
        # --- Step 1: Intercept Risky Action (drop_table) ---
        print("\n[1] Intercepting Risky Action (drop_table on production schema)...")
        request_1 = ToolCallRequest(
            session_id="sess_approval_101",
            agent_id="agent_db_admin",
            user_id="user_developer_mark",
            role="database_admin",
            tool_name="drop_table",
            action_type="DATABASE",
            target_resource="postgres://production/user_audit_logs",
            arguments={"table_name": "user_audit_logs"},
            task_summary="Clean up obsolete database audit logs",
        )

        res_1 = intercept_tool_call(request_1, db)
        print(f"    Event ID: {res_1.event_id}")
        print(f"    Verdict: {res_1.decision}")
        print(f"    Approval Required: {res_1.approval_required}")
        print(f"    Execution Allowed: {res_1.execution_allowed}")

        assert res_1.decision == "REQUIRE_APPROVAL", f"Expected REQUIRE_APPROVAL, got {res_1.decision}"
        assert res_1.approval_required == True, "Approval required must be True!"
        assert res_1.execution_allowed == False, "Initial execution allowed must be False!"

        # --- Step 2: Verify Pending Approval Record in PostgreSQL ---
        print("\n[2] Verifying Pending Approval Record Created in PostgreSQL...")
        approval_1 = get_approval_by_event_id(db, res_1.event_id)
        assert approval_1 is not None, "Failed to locate ApprovalModel in PostgreSQL!"

        print(f"    Approval ID: {approval_1.approval_id}")
        print(f"    Event ID: {approval_1.event_id}")
        print(f"    Status: {approval_1.status}")
        print(f"    Requested At: {approval_1.requested_at}")

        assert approval_1.status == "PENDING", f"Expected status PENDING, got {approval_1.status}"

        # --- Step 3: Human Reviewer Approves the Request ---
        print("\n[3] Human Reviewer ('sec_admin_sarah') Approving Action Request...")
        updated_event_1 = approve_action(
            db,
            event_id=res_1.event_id,
            reviewer="sec_admin_sarah",
            notes="Approved after verifying database backup snapshot."
        )

        print(f"    Updated Event ID: {updated_event_1.event_id}")
        print(f"    Approval Status: {updated_event_1.approval_status}")
        print(f"    Execution Allowed: {updated_event_1.execution_allowed}")
        print(f"    Decision Result: {updated_event_1.decision_result}")
        print(f"    Reviewer: {updated_event_1.reviewer}")
        print(f"    Decision Reason: {updated_event_1.decision_reason}")

        assert updated_event_1.approval_status == "APPROVED", "Approval status mismatch!"
        assert updated_event_1.execution_allowed == True, "Execution allowed should be True after approval!"
        assert updated_event_1.decision_result == "APPROVED", "Decision result mismatch!"

        # --- Step 4: Intercept Second Risky Action & Reject ---
        print("\n[4] Intercepting Second Risky Action & Testing Rejection Workflow...")
        request_2 = ToolCallRequest(
            session_id="sess_approval_102",
            agent_id="agent_db_admin",
            user_id="user_developer_mark",
            role="database_admin",
            tool_name="delete_all",
            action_type="DATABASE",
            target_resource="postgres://production/user_credentials",
            arguments={"table_name": "user_credentials"},
            task_summary="Delete all customer records",
        )

        res_2 = intercept_tool_call(request_2, db)
        print(f"    Event ID: {res_2.event_id} | Verdict: {res_2.decision}")

        print("    Human Reviewer ('sec_admin_sarah') Rejecting Action Request...")
        updated_event_2 = reject_action(
            db,
            event_id=res_2.event_id,
            reviewer="sec_admin_sarah",
            notes="Rejected: Attempt to delete production user credentials violates data retention policy."
        )

        print(f"    Approval Status: {updated_event_2.approval_status}")
        print(f"    Execution Allowed: {updated_event_2.execution_allowed}")
        print(f"    Decision Result: {updated_event_2.decision_result}")
        print(f"    Decision Reason: {updated_event_2.decision_reason}")

        assert updated_event_2.approval_status == "REJECTED", "Approval status mismatch!"
        assert updated_event_2.execution_allowed == False, "Execution allowed must remain False after rejection!"

        # --- Step 5: Query Audit Logs & Approvals List ---
        print("\n[5] Querying Full Audit Trail and Approvals in PostgreSQL...")
        all_approvals = list_approvals(db)
        print(f"    Total Approval Records in PostgreSQL: {len(all_approvals)}")
        for a in all_approvals[:5]:
            print(f"    - Approval ID: {a.approval_id} | Event: {a.event_id} | Status: {a.status:<8s} | Reviewer: {a.reviewer}")

        audit_events = list_audit_events(db, limit=10)
        print(f"\n    Total Audited Events in PostgreSQL: {len(audit_events)}")

        print("\n" + "=" * 80)
        print("[SUCCESS] AGENTSENTINEL PHASE 6 AUDIT & APPROVAL WORKFLOW DEMO VERIFIED")
        print("=" * 80)

    finally:
        db.close()

if __name__ == "__main__":
    run_audit_approval_demo()
