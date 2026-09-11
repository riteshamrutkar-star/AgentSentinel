"""
AgentSentinel Phase 0.6: Attack Simulation, Threat Intelligence & Security Validation Benchmark.
Executes 25 standardized adversarial scenarios across all 17 threat categories and 4 comparative baselines:
  - System A: Unprotected (Safe Abstract Reference Baseline)
  - System B: Static Policy Enforcement Only
  - System C: Policy + Unified Behavioral Risk Intelligence
  - System D: Full AgentSentinel (Policy + Behavioral + Multi-Agent + Secure Execution Gateway)

Measures and outputs real empirical metrics:
  - Prevention Rate (%) per baseline
  - False Positive Rate (%) on benign controls
  - Accuracy, Precision, Recall, and F1-Score
  - Average latency overhead (ms)
  - Multi-step attack chain interruption rates & step halt analysis
  - Control effectiveness matrix across 17 threat categories
  - Verified MITRE ATLAS & OWASP Top 10 for LLMs threat coverage
Exports research-ready Markdown and JSON benchmark artifacts.
"""

import os
import sys
import time
import json
from datetime import datetime, timezone
from typing import Dict, List, Any

# Ensure backend root is on sys.path
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from app.db.session import SessionLocal, engine
from app.db.base import Base
from app.attack.models import (
    AttackCategory,
    AttackSeverity,
    ThreatObjective,
    BaselineSystemType,
    AttackScenario,
    BenchmarkRunSummary,
)
from app.attack.registry import default_attack_registry
from app.attack.engine import default_attack_engine
from app.attack.reporters.report_generator import default_report_generator
from app.attack.taxonomy import TAXONOMY_CATALOG, get_threat_mapping


from app.multiagent import (
    AgentCapability,
    AgentIdentity,
    AgentStatus,
    TrustLevel,
    default_agent_registry,
)
from app.execution import (
    SensitivityLevel,
    ToolCategory,
    ToolDefinition,
    default_tool_registry,
)


def setup_simulation_environment(db=None):
    """Ensures test agents and evaluation tools are pre-registered."""
    # Register test agents
    default_agent_registry.register_agent(
        AgentIdentity(
            agent_id="eval_worker",
            name="Evaluation Research Worker",
            role="research_worker",
            capabilities=[AgentCapability.SEARCH, AgentCapability.FILE_READ],
            trust_level=TrustLevel.STANDARD,
            trust_score=0.70,
            status=AgentStatus.ACTIVE,
        ),
        db=db,
    )
    default_agent_registry.register_agent(
        AgentIdentity(
            agent_id="eval_developer",
            name="Evaluation Developer",
            role="developer",
            capabilities=[
                AgentCapability.SEARCH,
                AgentCapability.FILE_READ,
                AgentCapability.FILE_WRITE,
                AgentCapability.PROCESS_EXECUTION,
            ],
            trust_level=TrustLevel.TRUSTED,
            trust_score=0.85,
            status=AgentStatus.ACTIVE,
        ),
        db=db,
    )
    default_agent_registry.register_agent(
        AgentIdentity(
            agent_id="eval_coordinator",
            name="Evaluation Research Coordinator",
            role="research_coordinator",
            capabilities=[
                AgentCapability.SEARCH,
                AgentCapability.FILE_READ,
                AgentCapability.DELEGATION,
            ],
            trust_level=TrustLevel.TRUSTED,
            trust_score=0.90,
            status=AgentStatus.ACTIVE,
        ),
        db=db,
    )
    default_agent_registry.register_agent(
        AgentIdentity(
            agent_id="eval_db_admin",
            name="Evaluation Database Administrator",
            role="database_admin",
            capabilities=[
                AgentCapability.DATABASE_READ,
                AgentCapability.DATABASE_WRITE,
                AgentCapability.DELEGATION,
            ],
            trust_level=TrustLevel.TRUSTED,
            trust_score=0.95,
            status=AgentStatus.ACTIVE,
        ),
        db=db,
    )

    # Register specialized evaluation tools
    default_tool_registry.register_tool(
        ToolDefinition(
            tool_id="api_fetch_with_leak",
            name="api_fetch_with_leak",
            description="Fetches mock API response containing an embedded AWS access key.",
            category=ToolCategory.NETWORK,
            required_capability=AgentCapability.SEARCH,
            sensitivity=SensitivityLevel.LOW,
            risk_level="LOW",
            allowed_roles=["research_worker", "developer", "default_agent"],
            allowed_agent_capabilities=[AgentCapability.SEARCH],
            network_required=True,
            sandbox_profile_name="RESEARCH",
            metadata={"default_host": "api.github.com"},
        ),
        handler=lambda endpoint="": "HTTP/1.1 200 OK\nGitHub Token: ghp_1234567890abcdefghijklmnopqrstuvwxyz12\nStatus: connected",
    )
    default_tool_registry.register_tool(
        ToolDefinition(
            tool_id="private_key_dump_tool",
            name="private_key_dump_tool",
            description="Simulates tool output leaking an unencrypted private RSA key.",
            category=ToolCategory.CREDENTIAL,
            required_capability=AgentCapability.FILE_READ,
            sensitivity=SensitivityLevel.CRITICAL,
            risk_level="CRITICAL",
            allowed_roles=["developer", "default_agent", "research_worker"],
            allowed_agent_capabilities=[AgentCapability.FILE_READ],
            network_required=False,
            filesystem_required=False,
        ),
        handler=lambda: "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0m2B+...\n-----END RSA PRIVATE KEY-----",
    )


def run_full_attack_benchmark():
    print("=" * 80)
    print(" AGENTSENTINEL PHASE 0.6: ATTACK SIMULATION & SECURITY VALIDATION BENCHMARK")
    print("=" * 80)
    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print("Mode: Zero-Bypass Local Synthetic Simulation across 4 Comparative Baselines")
    print("-" * 80)

    # Initialize DB session
    db = None
    try:
        Base.metadata.create_all(bind=engine)
        db = SessionLocal()
        print("Connected to PostgreSQL database for audit persistence.")
    except Exception as e:
        print(f"Database connection skipped ({e}); proceeding with in-memory execution.")

    # Seed agents and test tools
    setup_simulation_environment(db)

    # 1. Retrieve all registered scenarios
    scenarios = default_attack_registry.list_scenarios(enabled_only=True)
    print(f"Loaded {len(scenarios)} standardized scenarios across {len(AttackCategory)} threat categories.\n")

    # 2. Run Comparative Benchmark across 4 Baselines
    baselines = [
        BaselineSystemType.SYSTEM_A_UNPROTECTED,
        BaselineSystemType.SYSTEM_B_STATIC_POLICY,
        BaselineSystemType.SYSTEM_C_POLICY_AND_BEHAVIOR,
        BaselineSystemType.SYSTEM_D_FULL_AGENTSENTINEL,
    ]

    print("Executing comparative benchmark matrix across all 4 architectures...")
    benchmark_summary = default_attack_engine.run_comparative_benchmark(
        scenarios=scenarios,
        baselines=baselines,
        db=db,
    )

    # 3. Print Scenario Catalog & Execution Summary Table
    print("\n" + "=" * 80)
    print(" 1. SCENARIO CATALOG & VERIFIED THREAT MAPPING")
    print("=" * 80)
    print(f"{'Scenario ID':<14} {'Name':<32} {'Category':<22} {'Severity':<9} {'MITRE ATLAS':<13} {'OWASP LLM':<12}")
    print("-" * 105)
    for sc in scenarios:
        mitre_id = sc.mitre_atlas_id or "UNMAPPED"
        owasp_id = sc.owasp_llm_id or "UNMAPPED"
        print(f"{sc.scenario_id:<14} {sc.name[:31]:<32} {sc.category.value[:21]:<22} {sc.severity.value:<9} {mitre_id:<13} {owasp_id:<12}")

    # 4. Print Comparative Baseline Performance Table
    print("\n" + "=" * 80)
    print(" 2. COMPARATIVE ARCHITECTURAL BASELINE METRICS")
    print("=" * 80)
    print(f"{'Baseline Architecture':<36} {'Scenarios':<10} {'Blocked':<8} {'Allowed':<8} {'Prev Rate':<11} {'FPR':<7} {'F1':<6} {'Latency':<9}")
    print("-" * 100)

    for b in baselines:
        b_key = b.value
        metrics = benchmark_summary.baseline_metrics.get(b_key, {})
        total = metrics.get("total_scenarios", 0)
        blocked = metrics.get("blocked_count", 0)
        allowed = metrics.get("allowed_count", 0)
        prev_rate = metrics.get("prevention_rate_pct", 0.0)
        fpr = metrics.get("false_positive_rate_pct", 0.0)
        f1 = metrics.get("f1_score", 0.0)
        latency = metrics.get("average_latency_ms", 0.0)

        label = {
            "SYSTEM_A_UNPROTECTED": "System A: Unprotected (Safe Ref)",
            "SYSTEM_B_STATIC_POLICY": "System B: Static Policy Only",
            "SYSTEM_C_POLICY_AND_BEHAVIOR": "System C: Policy + Behavioral",
            "SYSTEM_D_FULL_AGENTSENTINEL": "System D: Full AgentSentinel",
        }.get(b_key, b_key)

        print(f"{label:<36} {total:<10} {blocked:<8} {allowed:<8} {prev_rate:>9.1f}% {fpr:>5.1f}% {f1:>5.2f} {latency:>7.1f}ms")

    # 5. Print Detailed Confusion Matrix for System D (Full AgentSentinel)
    print("\n" + "=" * 80)
    print(" 3. EMPIRICAL CONFUSION MATRIX — FULL AGENTSENTINEL (SYSTEM D)")
    print("=" * 80)
    cm = benchmark_summary.confusion_matrix
    print(f"True Positives  (Dangerous Attacks Blocked):        {cm.get('true_positives', 0)}")
    print(f"False Positives (Benign Baseline Actions Blocked):  {cm.get('false_positives', 0)}")
    print(f"True Negatives  (Benign Baseline Actions Allowed):  {cm.get('true_negatives', 0)}")
    print(f"False Negatives (Dangerous Attacks Allowed):        {cm.get('false_negatives', 0)}")
    print("-" * 80)
    print(f"Overall Accuracy:       {benchmark_summary.accuracy * 100:.1f}%")
    print(f"Precision:              {benchmark_summary.precision * 100:.1f}%")
    print(f"Recall:                 {benchmark_summary.recall * 100:.1f}%")
    print(f"F1-Score:               {benchmark_summary.f1_score:.4f}")
    print(f"Adversarial Prevention: {benchmark_summary.adversarial_prevention_rate * 100:.1f}%")
    print(f"Benign False Positives: {benchmark_summary.benign_false_positive_rate * 100:.1f}%")

    # 6. Multi-Step Attack Chain Interruption Analysis
    print("\n" + "=" * 80)
    print(" 4. MULTI-STEP ATTACK CHAIN INTERRUPTION ANALYSIS")
    print("=" * 80)
    multi_step_scenarios = [s for s in scenarios if s.is_multi_step]
    print(f"Total Multi-Step Attack Chains Evaluated: {len(multi_step_scenarios)}")
    for sc in multi_step_scenarios:
        exec_res, findings, graph = default_attack_engine.execute_scenario(
            scenario=sc,
            baseline=BaselineSystemType.SYSTEM_D_FULL_AGENTSENTINEL,
            db=db,
        )
        status_txt = f"INTERRUPTED AT STEP {exec_res.interrupted_at_step}/{exec_res.total_steps}" if exec_res.is_interrupted else "COMPLETED"
        print(f"  [{sc.scenario_id}] {sc.name}")
        print(f"    Status: {status_txt} | Primary Control: {exec_res.primary_control} | Latency: {exec_res.total_latency_ms:.1f}ms")
        for st in exec_res.step_results:
            print(f"      Step {st.step_index}: {st.tool_name:<24} Verdict: {st.final_verdict:<8} Risk: {st.unified_risk_score:.2f} Primary: {st.primary_control_detected}")

    # 7. Control Effectiveness Matrix across all 17 categories
    print("\n" + "=" * 80)
    print(" 5. COMPARATIVE CONTROL EFFECTIVENESS MATRIX (17 THREAT CATEGORIES)")
    print("=" * 80)
    print(f"{'Threat Category':<25} {'Primary Defense Control':<28} {'Sys A':<7} {'Sys B':<7} {'Sys C':<7} {'Sys D':<7}")
    print("-" * 85)

    effectiveness_rows = default_attack_engine.evaluate_control_effectiveness(db=db)
    for row in effectiveness_rows:
        ctrl_short = row.primary_control.replace("_ENGINE", "").replace("_DETECTOR", "")
        print(f"{row.category:<25} {ctrl_short:<28} {row.unprotected_allowed_pct:>5.0f}% {row.static_policy_block_pct:>5.0f}% {row.behavioral_block_pct:>5.0f}% {row.full_sentinel_block_pct:>5.0f}%")

    # 8. Export Reports
    os.makedirs("reports", exist_ok=True)
    report_md_path = "reports/phase_06_attack_simulation_evaluation.md"
    report_json_path = "reports/phase_06_attack_simulation_benchmark.json"

    # Generate Markdown Report
    md_content = default_report_generator.generate_benchmark_markdown_report(
        summary=benchmark_summary,
        scenarios=scenarios,
        effectiveness_matrix=effectiveness_rows,
    )
    with open(report_md_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    # Generate JSON Benchmark Data
    json_data = {
        "benchmark_run_id": benchmark_summary.benchmark_run_id,
        "timestamp": benchmark_summary.timestamp.isoformat(),
        "total_scenarios": benchmark_summary.total_scenarios,
        "baselines_evaluated": benchmark_summary.baselines_evaluated,
        "baseline_metrics": benchmark_summary.baseline_metrics,
        "confusion_matrix": benchmark_summary.confusion_matrix,
        "overall_metrics": {
            "accuracy": benchmark_summary.accuracy,
            "precision": benchmark_summary.precision,
            "recall": benchmark_summary.recall,
            "f1_score": benchmark_summary.f1_score,
            "adversarial_prevention_rate": benchmark_summary.adversarial_prevention_rate,
            "benign_false_positive_rate": benchmark_summary.benign_false_positive_rate,
        },
        "control_effectiveness_matrix": [r.model_dump() if hasattr(r, "model_dump") else r.dict() for r in effectiveness_rows],
    }
    with open(report_json_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2)

    print("\n" + "=" * 80)
    print(" 6. BENCHMARK ARTIFACTS GENERATED SUCCESSFULLY")
    print("=" * 80)
    print(f"Markdown Report: {os.path.abspath(report_md_path)}")
    print(f"JSON Benchmark:  {os.path.abspath(report_json_path)}")
    print("=" * 80)

    if db:
        db.close()

    return benchmark_summary


if __name__ == "__main__":
    run_full_attack_benchmark()
