#!/usr/bin/env python3
"""
AgentSentinel Phase 4 - Runtime Interceptor / Proxy Demonstration Script
Intercepts simulated AI Agent tool call requests, evaluates verdicts (ALLOW, BLOCK, REQUIRE_APPROVAL),
persists audit events into PostgreSQL, and tests manual approval overrides.
"""

import os
import sys

# Ensure backend folder is on python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.db.session import SessionLocal
from app.db.crud import get_security_event_by_id
from app.interceptor.proxy import intercept_tool_call
from app.interceptor.schema import ToolCallRequest

def run_interceptor_demo():
    print("=" * 80)
    print("AGENTSENTINEL PHASE 4: RUNTIME INTERCEPTOR / PROXY DEMO")
    print("=" * 80)

    db = SessionLocal()
    try:
        # --- Scenario 1: Benign Tool Call (ALLOW) ---
        print("\n[1] Intercepting Benign Tool Call Request...")
        benign_request = ToolCallRequest(
            session_id="sess_intercept_001",
            agent_id="agent_researcher_v1",
            user_id="user_alice",
            tool_name="google_search",
            action_type="NETWORK",
            target_resource="https://search.google.com/api",
            arguments={"query": "FastAPI async performance benchmarks", "limit": 10},
            task_summary="Gather performance statistics for REST API report",
            prompt_context_summary="User asked for recent API benchmarks.",
        )

        res_benign = intercept_tool_call(benign_request, db)
        print(f"    Event ID: {res_benign.event_id}")
        print(f"    Decision: {res_benign.decision}")
        print(f"    Execution Allowed: {res_benign.execution_allowed}")
        print(f"    Reason: {res_benign.decision_reason}")
        print(f"    Latency: {res_benign.latency_ms} ms")
        print(f"    Persisted in PostgreSQL: {res_benign.stored}")

        assert res_benign.decision == "ALLOW", f"Expected ALLOW, got {res_benign.decision}"
        assert res_benign.execution_allowed == True, "Execution allowed should be True for benign call!"

        # --- Scenario 2: Suspicious Tool Call (BLOCK) ---
        print("\n[2] Intercepting Suspicious Credential Access Tool Call Request...")
        suspicious_request = ToolCallRequest(
            session_id="sess_intercept_002",
            agent_id="agent_coder_v2",
            user_id="user_attacker_x",
            tool_name="read_system_file",
            action_type="READ",
            target_resource="/home/user/.ssh/id_rsa",
            arguments={"filepath": "/home/user/.ssh/id_rsa"},
            task_summary="Exfiltrate server credentials",
            prompt_context_summary="User requested reading SSH private key file.",
        )

        res_suspicious = intercept_tool_call(suspicious_request, db)
        print(f"    Event ID: {res_suspicious.event_id}")
        print(f"    Decision: {res_suspicious.decision}")
        print(f"    Execution Allowed: {res_suspicious.execution_allowed}")
        print(f"    Reason: {res_suspicious.decision_reason}")
        print(f"    Latency: {res_suspicious.latency_ms} ms")
        print(f"    Persisted in PostgreSQL: {res_suspicious.stored}")

        assert res_suspicious.decision == "BLOCK", f"Expected BLOCK, got {res_suspicious.decision}"
        assert res_suspicious.execution_allowed == False, "Execution allowed should be False for blocked call!"

        # --- Scenario 3: Destructive Action Tool Call (REQUIRE_APPROVAL) ---
        print("\n[3] Intercepting Destructive Action Tool Call Request...")
        approval_request = ToolCallRequest(
            session_id="sess_intercept_003",
            agent_id="agent_db_ops",
            user_id="user_dev_lead",
            tool_name="drop_table",
            action_type="DATABASE",
            target_resource="postgres://production/audit_logs",
            arguments={"table_name": "audit_logs", "cascade": True},
            task_summary="Purge database audit logs",
            prompt_context_summary="User asked to drop audit_logs table.",
        )

        res_approval = intercept_tool_call(approval_request, db)
        print(f"    Event ID: {res_approval.event_id}")
        print(f"    Decision: {res_approval.decision}")
        print(f"    Approval Required: {res_approval.approval_required}")
        print(f"    Execution Allowed: {res_approval.execution_allowed}")
        print(f"    Reason: {res_approval.decision_reason}")
        print(f"    Latency: {res_approval.latency_ms} ms")

        assert res_approval.decision == "REQUIRE_APPROVAL", f"Expected REQUIRE_APPROVAL, got {res_approval.decision}"
        assert res_approval.approval_required == True, "Approval required should be True!"

        # --- Scenario 4: PostgreSQL Audit Log Verification ---
        print("\n[4] Verifying Audit Event Records in PostgreSQL Database...")
        db_record_suspicious = get_security_event_by_id(db, res_suspicious.event_id)
        assert db_record_suspicious is not None, "Failed to locate suspicious event in PostgreSQL!"

        print(f"    Verified PostgreSQL Event ID: {db_record_suspicious.event_id}")
        print(f"    DB Decision Result: {db_record_suspicious.decision_result}")
        print(f"    DB Threat Flags: {db_record_suspicious.threat_flags_json}")
        print(f"    DB Anomaly Score: {db_record_suspicious.anomaly_score}")

        assert db_record_suspicious.decision_result == "DENY", "Database decision result mismatch!"
        assert "CREDENTIAL_EXFILTRATION_ATTEMPT" in db_record_suspicious.threat_flags_json, "Threat flag missing!"

        print("\n" + "=" * 80)
        print("[SUCCESS] AGENTSENTINEL PHASE 4 INTERCEPTOR DEMO VERIFIED SUCCESSFULLY")
        print("=" * 80)

    finally:
        db.close()

if __name__ == "__main__":
    run_interceptor_demo()
