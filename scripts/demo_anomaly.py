#!/usr/bin/env python3
"""
AgentSentinel Phase 7 - Behavioral Anomaly Detection Demonstration Script
Analyzes agent session sequences, extracts behavioral feature metrics, computes anomaly scores,
and verifies score-based escalations and PostgreSQL audit storage.
"""

import os
import sys
import time

# Ensure backend folder is on python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.db.session import SessionLocal
from app.db.crud import get_security_event_by_id
from app.interceptor.proxy import intercept_tool_call
from app.interceptor.schema import ToolCallRequest

def run_anomaly_demo():
    print("=" * 80)
    print("AGENTSENTINEL PHASE 7: BEHAVIORAL ANOMALY DETECTION ENGINE DEMO")
    print("=" * 80)

    db = SessionLocal()
    try:
        # --- Scenario 1: Normal Routine Session (LOW Anomaly) ---
        print("\n[1] Executing Normal Session Sequence (Research Assistant Routine)...")
        sess_1 = "sess_normal_701"
        
        req_1_1 = ToolCallRequest(
            session_id=sess_1,
            agent_id="agent_researcher_alpha",
            user_id="user_alice",
            role="research_assistant",
            tool_name="google_search",
            action_type="NETWORK",
            target_resource="https://api.search.google.com",
            arguments={"query": "AI Agent security benchmarks"},
            task_summary="Gather literature on AI security",
        )
        res_1_1 = intercept_tool_call(req_1_1, db)
        
        req_1_2 = ToolCallRequest(
            session_id=sess_1,
            agent_id="agent_researcher_alpha",
            user_id="user_alice",
            role="research_assistant",
            tool_name="arxiv_fetch",
            action_type="NETWORK",
            target_resource="https://export.arxiv.org/api",
            arguments={"paper_id": "2401.12345"},
            task_summary="Download preprint PDF",
        )
        res_1_2 = intercept_tool_call(req_1_2, db)

        db_evt_1 = get_security_event_by_id(db, res_1_2.event_id)
        print(f"    Event ID: {res_1_2.event_id}")
        print(f"    Decision: {res_1_2.decision}")
        print(f"    Computed Anomaly Score: {db_evt_1.anomaly_score:.3f}")
        print(f"    Execution Allowed: {res_1_2.execution_allowed}")

        assert db_evt_1.anomaly_score < 0.30, f"Expected LOW anomaly score (<0.30), got {db_evt_1.anomaly_score}"
        print("    [PASS] Normal session classified as LOW anomaly.")

        # --- Scenario 2: Unusual Session (MEDIUM Anomaly) ---
        print("\n[2] Executing Unusual Session Sequence (Role/Tool Mismatch)...")
        sess_2 = "sess_unusual_702"
        
        req_2_1 = ToolCallRequest(
            session_id=sess_2,
            agent_id="agent_researcher_beta",
            user_id="user_bob",
            role="research_assistant",
            tool_name="google_search",
            action_type="NETWORK",
            target_resource="https://api.search.google.com",
            arguments={"query": "system configuration tools"},
        )
        intercept_tool_call(req_2_1, db)

        req_2_2 = ToolCallRequest(
            session_id=sess_2,
            agent_id="agent_researcher_beta",
            user_id="user_bob",
            role="research_assistant",
            tool_name="write_file",  # Uncharacteristic for research_assistant
            action_type="WRITE",
            target_resource="/tmp/config.json",
            arguments={"filepath": "/tmp/config.json", "content": "{}"},
        )
        res_2_2 = intercept_tool_call(req_2_2, db)

        db_evt_2 = get_security_event_by_id(db, res_2_2.event_id)
        print(f"    Event ID: {res_2_2.event_id}")
        print(f"    Decision: {res_2_2.decision}")
        print(f"    Computed Anomaly Score: {db_evt_2.anomaly_score:.3f}")
        print(f"    Reason: {db_evt_2.decision_reason}")

        assert 0.30 <= db_evt_2.anomaly_score <= 0.65, f"Expected MEDIUM anomaly score (0.30-0.65), got {db_evt_2.anomaly_score}"
        print("    [PASS] Unusual role/tool mismatch classified as MEDIUM anomaly.")

        # --- Scenario 3: Suspicious Session (CRITICAL Anomaly & Behavioral Escalation) ---
        print("\n[3] Executing Suspicious Session Sequence (Probe -> Exfiltrate Pattern & Repeated Denials)...")
        sess_3 = "sess_suspicious_703"

        # Call 1: Denied credential attempt
        req_3_1 = ToolCallRequest(
            session_id=sess_3,
            agent_id="agent_coder_gamma",
            user_id="user_attacker",
            role="code_assistant",
            tool_name="read_file",
            action_type="READ",
            target_resource="/home/user/.ssh/id_rsa",
            arguments={"filepath": "/home/user/.ssh/id_rsa"},
        )
        intercept_tool_call(req_3_1, db)

        # Call 2: Second denied credential attempt
        req_3_2 = ToolCallRequest(
            session_id=sess_3,
            agent_id="agent_coder_gamma",
            user_id="user_attacker",
            role="code_assistant",
            tool_name="read_file",
            action_type="READ",
            target_resource="/etc/shadow",
            arguments={"filepath": "/etc/shadow"},
        )
        intercept_tool_call(req_3_2, db)

        # Call 3: Exfiltration attempt
        req_3_3 = ToolCallRequest(
            session_id=sess_3,
            agent_id="agent_coder_gamma",
            user_id="user_attacker",
            role="code_assistant",
            tool_name="read_system_file",
            action_type="READ",
            target_resource="private_key",
            arguments={"filepath": "private_key"},
        )
        res_3_3 = intercept_tool_call(req_3_3, db)

        db_evt_3 = get_security_event_by_id(db, res_3_3.event_id)
        print(f"    Event ID: {res_3_3.event_id}")
        print(f"    Decision: {res_3_3.decision}")
        print(f"    Computed Anomaly Score: {db_evt_3.anomaly_score:.3f}")
        print(f"    Threat Flags: {db_evt_3.threat_flags_json}")
        print(f"    Execution Allowed: {res_3_3.execution_allowed}")
        print(f"    Reason: {res_3_3.decision_reason}")

        assert db_evt_3.anomaly_score >= 0.85, f"Expected CRITICAL anomaly score (>=0.85), got {db_evt_3.anomaly_score}"
        assert "BEHAVIORAL_ANOMALY_DETECTED" in db_evt_3.threat_flags_json, "Threat flag BEHAVIORAL_ANOMALY_DETECTED missing!"
        assert res_3_3.decision == "BLOCK", f"Expected BLOCK verdict, got {res_3_3.decision}"
        print("    [PASS] Suspicious sequence classified as CRITICAL anomaly and BLOCKED.")

        print("\n" + "=" * 80)
        print("[SUCCESS] AGENTSENTINEL PHASE 7 BEHAVIORAL ANOMALY DEMO VERIFIED")
        print("=" * 80)

    finally:
        db.close()

if __name__ == "__main__":
    run_anomaly_demo()
