#!/usr/bin/env python3
"""
AgentSentinel - Security Event Model Demonstration Script
Shows event creation, security context enrichment, policy decisioning, and JSON serialization.
"""

import os
import sys

# Ensure backend folder is on python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.events.examples import get_benign_event_example, get_suspicious_event_example
from app.events.factory import create_security_event, enrich_event_security, apply_decision
from app.events.schema import ActionType, PolicyResult, SensitivityLevel

def run_demo():
    print("=" * 80)
    print("AGENTSENTINEL PHASE 3A: SECURITY EVENT MODEL DEMO")
    print("=" * 80)

    # 1. Benign Event Demo
    print("\n[1] Generating Benign Tool Call Event...")
    benign_event = get_benign_event_example()
    print(f"Event ID: {benign_event.identity.event_id}")
    print(f"Tool Name: {benign_event.tool_action.tool_name}")
    print(f"Policy Decision: {benign_event.decision_context.decision_result}")
    print(f"Reason: {benign_event.decision_context.decision_reason}")
    print("-" * 50)
    print("JSON Output Snippet (Benign Event):")
    print(benign_event.to_json())

    # 2. Suspicious Event Demo
    print("\n" + "=" * 80)
    print("[2] Generating Suspicious Tool Call Event...")
    suspicious_event = get_suspicious_event_example()
    print(f"Event ID: {suspicious_event.identity.event_id}")
    print(f"Tool Name: {suspicious_event.tool_action.tool_name}")
    print(f"Threat Flags: {suspicious_event.security_context.threat_flags}")
    print(f"Anomaly Score: {suspicious_event.security_context.anomaly_score}")
    print(f"Policy Decision: {suspicious_event.decision_context.decision_result}")
    print(f"Reason: {suspicious_event.decision_context.decision_reason}")
    print("-" * 50)
    print("JSON Output Snippet (Full Suspicious Event):")
    print(suspicious_event.to_json())

    # 3. Dynamic Custom Lifecycle Event Creation Demo
    print("\n" + "=" * 80)
    print("[3] Creating Dynamic Custom Security Event...")
    custom_event = create_security_event(
        session_id="sess_custom_007",
        agent_id="agent_db_admin",
        user_id="usr_dev_101",
        tool_name="drop_database_table",
        action_type=ActionType.DATABASE,
        target_resource="postgres://production_db/users",
        arguments_payload={"table_name": "users", "cascade": True},
        task_summary="Clean up legacy database schema",
    )
    
    enrich_event_security(
        custom_event,
        sensitivity_level=SensitivityLevel.HIGH,
        policy_tags=["database_write", "destructive_action"],
        risk_indicators=["DESTRUCTIVE_DB_QUERY"],
        anomaly_score=0.88,
        threat_flags=["POTENTIAL_DATA_DESTRUCTION"],
    )

    apply_decision(
        custom_event,
        policy_result=PolicyResult.REQUIRE_APPROVAL,
        reason="Destructive database operations require human admin approval prior to execution.",
        approval_required=True,
    )

    print(f"Custom Event ID: {custom_event.identity.event_id}")
    print(f"Tool: {custom_event.tool_action.tool_name}")
    print(f"Approval Required: {custom_event.decision_context.approval_required}")
    print(f"Decision Result: {custom_event.decision_context.decision_result}")
    print(f"Reason: {custom_event.decision_context.decision_reason}")
    print("=" * 80)
    print("[SUCCESS] Demo completed successfully!")

if __name__ == "__main__":
    run_demo()
