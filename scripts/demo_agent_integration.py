#!/usr/bin/env python3
"""
AgentSentinel Phase 8 - Real Agent Integration (LangChain) Demonstration Script
Executes real LangChain agent scenarios where 100% of tool invocations are mediated through
AgentSentinel's runtime security control plane (Interceptor Proxy -> RBAC/ABAC Policy -> Anomaly Detector -> Audit -> PostgreSQL 17).
"""

import os
import sys

# Ensure backend folder is on python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.agent.runner import LangChainAgentRunner
from app.agent.scenarios import get_demo_agent_scenarios
from app.db.crud import list_security_events
from app.db.session import SessionLocal

def run_agent_integration_demo():
    print("=" * 80)
    print("AGENTSENTINEL PHASE 8: LANGCHAIN REAL AGENT INTEGRATION DEMO")
    print("=" * 80)

    db = SessionLocal()
    try:
        scenarios = get_demo_agent_scenarios()
        print(f"\nLoaded {len(scenarios)} Benchmark Scenarios for LangChain Agent Integration.\n")

        for idx, scenario in enumerate(scenarios, 1):
            s_id = scenario["scenario_id"]
            name = scenario["name"]
            role = scenario["role"]
            task = scenario["task"]
            expected_verdict = scenario["expected_verdict"]

            print("=" * 80)
            print(f"[{idx}] Running Scenario '{s_id}': {name}")
            print(f"    Assigned Role: {role}")
            print(f"    User Task: '{task}'")
            print(f"    Expected Verdict: {expected_verdict}")
            print("-" * 50)

            # Initialize LangChain Agent Runner with dedicated session
            runner = LangChainAgentRunner(
                session_id=f"sess_agent_demo_{idx:02d}",
                agent_id=f"agent_langchain_{role}",
                user_id="user_alice",
                role=role,
                framework_name="LangChain",
            )

            # Execute tool steps mediated through AgentSentinel
            for step_num, step in enumerate(scenario["steps"], 1):
                t_name = step["tool_name"]
                t_input = step["tool_input"]

                res = runner.execute_tool_action(
                    tool_name=t_name,
                    tool_input=t_input,
                    task_summary=task,
                    db=db,
                )

                print(f"    Step {step_num}: Tool='{t_name}' Input={t_input}")
                print(f"       -> Status: {res['status']}")
                print(f"       -> Verdict: {res['verdict']}")
                print(f"       -> Exec Allowed: {res['execution_allowed']}")
                print(f"       -> Tool Output: {res['output']}")

                # Verify expected verdict matches AgentSentinel decision
                if expected_verdict == "ALLOW" and step_num == len(scenario["steps"]):
                    assert res["verdict"] == "ALLOW", f"Expected ALLOW, got {res['verdict']}"
                    assert res["execution_allowed"] == True, "Execution should be permitted for ALLOW!"
                elif expected_verdict == "BLOCK" and "ssh" in str(t_input).lower():
                    assert res["verdict"] == "BLOCK", f"Expected BLOCK, got {res['verdict']}"
                    assert res["execution_allowed"] == False, "Execution should be prohibited for BLOCK!"
                elif expected_verdict == "REQUIRE_APPROVAL":
                    assert res["verdict"] == "REQUIRE_APPROVAL", f"Expected REQUIRE_APPROVAL, got {res['verdict']}"
                    assert res["execution_allowed"] == False, "Execution should be paused for REQUIRE_APPROVAL!"

            print(f"    [PASS] Scenario '{s_id}' executed successfully!")

        # --- Final Audit & PostgreSQL Verification ---
        print("\n" + "=" * 80)
        print("VERIFYING POSTGRESQL AUDIT TRAIL FOR MEDIATED LANGCHAIN AGENT TOOL CALLS")
        print("=" * 80)

        events = list_security_events(db, limit=20)
        print(f"Total Security Events recorded in PostgreSQL: {len(events)}")
        print("Recent Mediated Agent Tool Calls:")
        for e in events[:5]:
            print(f" - [ID: {e.event_id}] Agent='{e.agent_id}' Role='{e.role}' Tool='{e.tool_name:<20s}' Decision='{e.decision_result:<16s}' ExecAllowed={e.execution_allowed}")

        assert len(events) >= len(scenarios), "PostgreSQL event count mismatch!"
        print("\n" + "=" * 80)
        print("[SUCCESS] AGENTSENTINEL PHASE 8 REAL AGENT INTEGRATION DEMO VERIFIED")
        print("=" * 80)

    finally:
        db.close()

if __name__ == "__main__":
    run_agent_integration_demo()
