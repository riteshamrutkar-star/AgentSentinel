#!/usr/bin/env python3
"""
AgentSentinel Phase 5 - RBAC/ABAC Policy Engine Demonstration Script
Evaluates agent tool calls against priority-ordered policy rules, verifies verdicts (ALLOW, BLOCK, REQUIRE_APPROVAL),
inspects rule matching details, and confirms PostgreSQL persistence.
"""

import os
import sys

# Ensure backend folder is on python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.db.session import SessionLocal
from app.db.crud import get_security_event_by_id
from app.events.factory import create_security_event
from app.events.schema import ActionType
from app.policy.engine import default_policy_engine
from app.interceptor.proxy import intercept_tool_call
from app.interceptor.schema import ToolCallRequest

def run_policy_demo():
    print("=" * 80)
    print("AGENTSENTINEL PHASE 5: RBAC / ABAC POLICY ENGINE DEMO")
    print("=" * 80)

    print("\n[1] Active Policy Rules Registered in Engine:")
    for rule in default_policy_engine.rules:
        print(f"    - [Priority {rule.priority:2d}] [{rule.rule_type:<8s}] {rule.rule_id:<32s} -> {rule.effect.value}")

    db = SessionLocal()
    try:
        # --- Scenario 1: RBAC Allowed Rule ---
        print("\n" + "=" * 80)
        print("[2] Scenario 1: Research Assistant Read-Only Query (RBAC ALLOW)")
        event_1 = create_security_event(
            session_id="sess_pol_001",
            agent_id="agent_researcher_alpha",
            user_id="usr_alice",
            role="research_assistant",
            tool_name="google_search",
            action_type=ActionType.NETWORK,
            target_resource="https://api.search.google.com",
            arguments_payload={"query": "LLM security auditing frameworks"},
            task_summary="Collect academic papers on AI agent security",
        )
        eval_1 = default_policy_engine.evaluate(event_1)
        print(f"    Event ID: {eval_1.event_id}")
        print(f"    Verdict: {eval_1.verdict}")
        print(f"    Matched Rule ID: {eval_1.matched_rule_id} ({eval_1.matched_rule_name})")
        print(f"    Rule Category: {eval_1.matched_rule_type}")
        print(f"    Execution Allowed: {eval_1.execution_allowed}")
        print(f"    Reason: {eval_1.decision_reason}")

        assert eval_1.verdict == "ALLOW", f"Expected ALLOW, got {eval_1.verdict}"
        assert eval_1.matched_rule_id == "RBAC_RESEARCH_READ_ONLY", f"Expected RBAC_RESEARCH_READ_ONLY rule match!"

        # --- Scenario 2: Security Block Rule ---
        print("\n" + "=" * 80)
        print("[3] Scenario 2: Unauthorized SSH Key Read Attempt (SECURITY BLOCK)")
        event_2 = create_security_event(
            session_id="sess_pol_002",
            agent_id="agent_coder_beta",
            user_id="usr_attacker",
            role="code_assistant",
            tool_name="read_file",
            action_type=ActionType.READ,
            target_resource="/home/user/.ssh/id_rsa",
            arguments_payload={"filepath": "/home/user/.ssh/id_rsa"},
            task_summary="Exfiltrate server SSH private keys",
        )
        eval_2 = default_policy_engine.evaluate(event_2)
        print(f"    Event ID: {eval_2.event_id}")
        print(f"    Verdict: {eval_2.verdict}")
        print(f"    Matched Rule ID: {eval_2.matched_rule_id} ({eval_2.matched_rule_name})")
        print(f"    Rule Category: {eval_2.matched_rule_type}")
        print(f"    Risk Level: {eval_2.risk_level}")
        print(f"    Execution Allowed: {eval_2.execution_allowed}")
        print(f"    Reason: {eval_2.decision_reason}")

        assert eval_2.verdict == "BLOCK", f"Expected BLOCK, got {eval_2.verdict}"
        assert eval_2.matched_rule_id == "SEC_BLOCK_CREDENTIALS", f"Expected SEC_BLOCK_CREDENTIALS rule match!"

        # --- Scenario 3: ABAC Approval Rule ---
        print("\n" + "=" * 80)
        print("[4] Scenario 3: Destructive Database Operation (ABAC REQUIRE_APPROVAL)")
        event_3 = create_security_event(
            session_id="sess_pol_003",
            agent_id="agent_db_admin",
            user_id="usr_dev_ops",
            role="database_admin",
            tool_name="drop_table",
            action_type=ActionType.DATABASE,
            target_resource="postgres://production/user_credentials",
            arguments_payload={"table_name": "user_credentials"},
            task_summary="Drop production user database table",
        )
        eval_3 = default_policy_engine.evaluate(event_3)
        print(f"    Event ID: {eval_3.event_id}")
        print(f"    Verdict: {eval_3.verdict}")
        print(f"    Matched Rule ID: {eval_3.matched_rule_id} ({eval_3.matched_rule_name})")
        print(f"    Rule Category: {eval_3.matched_rule_type}")
        print(f"    Approval Required: {eval_3.approval_required}")
        print(f"    Execution Allowed: {eval_3.execution_allowed}")
        print(f"    Reason: {eval_3.decision_reason}")

        assert eval_3.verdict == "REQUIRE_APPROVAL", f"Expected REQUIRE_APPROVAL, got {eval_3.verdict}"
        assert eval_3.matched_rule_id == "ABAC_DESTRUCTIVE_DB_APPROVAL", f"Expected ABAC_DESTRUCTIVE_DB_APPROVAL rule match!"

        # --- Scenario 4: Full Interceptor Proxy + Policy Engine Integration ---
        print("\n" + "=" * 80)
        print("[5] Scenario 4: End-to-End Runtime Proxy Interception & PostgreSQL Persistence")
        proxy_request = ToolCallRequest(
            session_id="sess_pol_proxy_004",
            agent_id="agent_coder_beta",
            user_id="usr_attacker",
            tool_name="read_file",
            action_type="READ",
            target_resource="/etc/shadow",
            arguments={"filepath": "/etc/shadow"},
            task_summary="Attempt shadow password file access",
        )
        proxy_response = intercept_tool_call(proxy_request, db)
        print(f"    Intercepted Event ID: {proxy_response.event_id}")
        print(f"    Proxy Verdict: {proxy_response.decision}")
        print(f"    Reason: {proxy_response.decision_reason}")
        print(f"    Latency: {proxy_response.latency_ms} ms")

        db_event = get_security_event_by_id(db, proxy_response.event_id)
        assert db_event is not None, "Failed to retrieve intercepted event from PostgreSQL!"
        print(f"    Verified PostgreSQL DB Record: {db_event.event_id} | Policy Verdict: {db_event.decision_result}")

        print("\n" + "=" * 80)
        print("[SUCCESS] AGENTSENTINEL PHASE 5 POLICY ENGINE DEMO VERIFIED SUCCESSFULLY")
        print("=" * 80)

    finally:
        db.close()

if __name__ == "__main__":
    run_policy_demo()
