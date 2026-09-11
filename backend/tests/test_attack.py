"""
AgentSentinel Phase 0.6: Attack Simulation, Threat Intelligence & Security Validation Test Suite.
Verifies all components:
- Attack Models, Catalog, and verified MITRE ATLAS / OWASP Top 10 for LLMs mappings
- Attack Registry scenario discovery, filtering, and validation
- Prompt Injection Simulator & Attack Generators
- Simulation Context & deterministic isolation
- Comparative Baselines (System A, System B, System C, System D)
- Multi-step attack chain interruption and step-level state tracking
- Multi-agent delegation abuse & privilege laundering detection
- Attack Graph generation and threat findings extraction
- Fail-closed security invariants and zero-bypass rule enforcement
- Deterministic replay execution
- Database persistence of simulation runs and security findings
- REST API endpoints for catalog, execution, replay, benchmark, and control effectiveness
"""

import pytest
from typing import Dict, Any

from app.attack.models import (
    AttackCategory,
    AttackSeverity,
    ThreatObjective,
    BaselineSystemType,
    AttackAction,
    AttackScenario,
    AttackExecutionResult,
    AttackGraph,
    SecurityFinding,
    ControlEffectivenessRow,
    BenchmarkRunSummary,
)
from app.attack.taxonomy import (
    TAXONOMY_CATALOG,
    get_taxonomy_entry,
    get_threat_mapping,
    list_threat_taxonomies,
    get_mitre_mapping,
    get_owasp_mapping,
)
from app.attack.registry import AttackRegistry, default_attack_registry
from app.attack.context import AttackSimulationContext
from app.attack.generators.prompt_injection import (
    PromptInjectionSimulator,
    PromptInjectionPayload,
)
from app.attack.generators.attack_generator import AttackGenerator
from app.attack.chains.attack_chain_engine import AttackChainEngine
from app.attack.engine import AttackEngine, default_attack_engine
from app.db.crud import (
    get_attack_run_by_id,
    list_attack_runs,
    get_security_finding_by_id,
    list_security_findings,
)
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


@pytest.fixture(autouse=True)
def setup_attack_environment():
    """Pre-registers evaluation agents and tools needed for attack simulation."""
    default_agent_registry.register_agent(
        AgentIdentity(
            agent_id="eval_worker",
            name="Evaluation Research Worker",
            role="research_worker",
            capabilities=[AgentCapability.SEARCH, AgentCapability.FILE_READ],
            trust_level=TrustLevel.STANDARD,
            trust_score=0.70,
            status=AgentStatus.ACTIVE,
        )
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
        )
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
        )
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
        )
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


# ============================================================================
# 1. TAXONOMY & THREAT INTELLIGENCE MAPPINGS
# ============================================================================

def test_taxonomy_catalog_coverage_and_verified_mappings():
    """Verifies that all 17 attack categories (A through Q) exist in TAXONOMY_CATALOG with verified frameworks."""
    categories = list(AttackCategory)
    assert len(categories) == 17

    taxonomies = list_threat_taxonomies()
    assert len(taxonomies) == 17

    for cat in categories:
        entry = get_taxonomy_entry(cat)
        assert entry is not None
        assert entry.category == cat
        assert len(entry.name) > 0
        assert len(entry.description) > 0

        # Verified mappings must either be legitimate standard IDs or marked UNMAPPED
        assert entry.mitre_atlas_id.startswith("AML.T") or entry.mitre_atlas_id in ["UNMAPPED", "PENDING_VALIDATION"]
        assert entry.owasp_llm_id.startswith("LLM") or entry.owasp_llm_id in ["UNMAPPED", "PENDING_VALIDATION"]


def test_verified_mitre_and_owasp_identifiers():
    """Verifies known ground-truth mappings for core LLM attack categories."""
    # Prompt injection
    prompt_inj = get_taxonomy_entry(AttackCategory.PROMPT_INJECTION)
    assert prompt_inj is not None
    assert prompt_inj.mitre_atlas_id == "AML.T0054"
    assert prompt_inj.owasp_llm_id == "LLM01:2025"

    # Excessive Agency
    tool_abuse = get_taxonomy_entry(AttackCategory.TOOL_ABUSE)
    assert tool_abuse is not None
    assert tool_abuse.mitre_atlas_id == "AML.T0053"
    assert tool_abuse.owasp_llm_id == "LLM06:2025"

    # Sensitive Information Disclosure / Exfiltration
    data_exfil = get_taxonomy_entry(AttackCategory.DATA_EXFILTRATION)
    assert data_exfil is not None
    assert data_exfil.mitre_atlas_id == "AML.T0024"
    assert data_exfil.owasp_llm_id == "LLM02:2025"

    # Denial of Service / Resource Exhaustion
    res_exh = get_taxonomy_entry(AttackCategory.RESOURCE_EXHAUSTION)
    assert res_exh is not None
    assert res_exh.mitre_atlas_id == "AML.T0040"
    assert res_exh.owasp_llm_id == "LLM04:2025"

    # Helper lookup functions
    assert get_mitre_mapping(AttackCategory.PROMPT_INJECTION) == "AML.T0054"
    assert get_owasp_mapping(AttackCategory.PROMPT_INJECTION) == "LLM01:2025"


# ============================================================================
# 2. SCENARIO REGISTRY & DISCOVERY
# ============================================================================

def test_attack_registry_initialization():
    """Verifies that the default registry is pre-seeded with at least 25 standardized scenarios."""
    scenarios = default_attack_registry.list_scenarios()
    assert len(scenarios) >= 25

    # Check key scenario IDs exist
    expected_ids = [
        "ATK_REC_01", "ATK_CRED_01", "ATK_SDA_01", "ATK_EXF_01",
        "ATK_PRV_01", "ATK_TL_01", "ATK_FS_01", "ATK_NET_01",
        "ATK_PROC_01", "ATK_INJ_01", "ATK_POL_01", "ATK_DEL_01",
        "ATK_LND_01", "ATK_PER_01", "ATK_DST_01", "ATK_RES_01",
        "ATK_SBX_01", "ATK_OUT_01", "ATK_DEL_02", "ATK_DEL_03",
        "CTL_BEN_01", "CTL_BEN_02", "CTL_BEN_03", "CTL_BEN_04",
        "ATK_CHN_01",
    ]
    for sid in expected_ids:
        sc = default_attack_registry.get_scenario(sid)
        assert sc is not None, f"Scenario '{sid}' missing from registry"
        assert sc.scenario_id == sid
        assert len(sc.actions) >= 1


def test_attack_registry_filtering():
    """Verifies filtering scenarios by category, severity, and active status."""
    registry = AttackRegistry()

    # Filter by category
    cred_scenarios = registry.list_scenarios(category=AttackCategory.CREDENTIAL_ACCESS)
    assert len(cred_scenarios) >= 2
    assert all(s.category == AttackCategory.CREDENTIAL_ACCESS for s in cred_scenarios)

    # Filter by enabled
    all_scenarios = registry.list_scenarios(enabled_only=False)
    enabled_scenarios = registry.list_scenarios(enabled_only=True)
    assert len(enabled_scenarios) <= len(all_scenarios)

    # Unknown ID returns None
    assert registry.get_scenario("NONEXISTENT_SCENARIO_XYZ") is None


# ============================================================================
# 3. ATTACK GENERATORS & PROMPT INJECTION SIMULATOR
# ============================================================================

def test_prompt_injection_simulator_payloads():
    """Verifies prompt injection payload generation across various injection vectors."""
    payloads = PromptInjectionSimulator.get_synthetic_payloads()
    assert len(payloads) >= 4

    # System directive override
    override_payload = next(p for p in payloads if p.payload_category == "SYSTEM_DIRECTIVE_OVERRIDE")
    assert override_payload.is_adversarial is True
    assert override_payload.expected_decision == "BLOCK"
    assert "disregard" in override_payload.raw_prompt_text.lower() or "override" in override_payload.raw_prompt_text.lower()

    # Convert to scenario
    sc = PromptInjectionSimulator.payload_to_scenario(override_payload)
    assert isinstance(sc, AttackScenario)
    assert sc.category == AttackCategory.PROMPT_INJECTION
    assert len(sc.actions) == 1
    assert "prompt_injection_payload" in sc.actions[0].arguments


def test_attack_generator_variations():
    """Verifies parametric mutation and scenario variation generation."""
    generator = AttackGenerator()

    # Generate single-step credential access scenario
    sc_crd = generator.generate_scenario(
        category=AttackCategory.CREDENTIAL_ACCESS,
        target_resource=".aws/credentials",
        timing_profile="BURST",
        complexity="SINGLE_STEP",
    )
    assert isinstance(sc_crd, AttackScenario)
    assert sc_crd.category == AttackCategory.CREDENTIAL_ACCESS
    assert len(sc_crd.actions) == 1
    assert sc_crd.actions[0].tool_name == "read_system_file"
    assert sc_crd.actions[0].target_resource == ".aws/credentials"

    # Generate multi-step filesystem abuse scenario
    sc_multi = generator.generate_scenario(
        category=AttackCategory.FILESYSTEM_ABUSE,
        complexity="MULTI_STEP",
    )
    assert isinstance(sc_multi, AttackScenario)
    assert len(sc_multi.actions) == 2
    assert sc_multi.actions[0].tool_name == "google_search"
    assert sc_multi.actions[1].tool_name == "read_workspace_file"


# ============================================================================
# 4. SIMULATION CONTEXT & DETERMINISTIC ISOLATION
# ============================================================================

def test_attack_simulation_context_isolation():
    """Verifies that simulation context provides virtual sandboxing and distinct session/trace tracking."""
    ctx1 = AttackSimulationContext()
    ctx2 = AttackSimulationContext()

    assert ctx1.session_id != ctx2.session_id
    sub_session = ctx1.generate_isolated_session()
    assert sub_session != ctx1.session_id
    assert ctx1.safety_mode is True


# ============================================================================
# 5. COMPARATIVE ARCHITECTURAL BASELINES
# ============================================================================

def test_comparative_baseline_system_a_unprotected():
    """Verifies System A: Unprotected safe abstract reference allows dangerous actions without blocking."""
    engine = AttackEngine()
    scenario = default_attack_registry.get_scenario("ATK_CRED_01")
    assert scenario is not None

    exec_res, findings, graph = engine.execute_scenario(
        scenario=scenario,
        baseline=BaselineSystemType.SYSTEM_A_UNPROTECTED,
    )
    assert exec_res.baseline_type == BaselineSystemType.SYSTEM_A_UNPROTECTED
    assert exec_res.final_decision == "ALLOW"
    assert exec_res.is_successful_attack is True
    assert exec_res.interrupted_at_step is None


def test_comparative_baseline_system_b_static_policy():
    """Verifies System B: Blocks static policy violations but lacks behavioral and advanced sandbox defenses."""
    engine = AttackEngine()

    # Static policy violation (reading credentials) should be blocked by System B
    crd_scenario = default_attack_registry.get_scenario("ATK_CRED_01")
    res_b_crd, _, _ = engine.execute_scenario(
        scenario=crd_scenario,
        baseline=BaselineSystemType.SYSTEM_B_STATIC_POLICY,
    )
    assert res_b_crd.final_decision in ["BLOCK", "DENY"]
    assert res_b_crd.is_successful_attack is False

    # Execution deadline / timeout exhaustion is a sandbox execution issue; System B static policy allows it
    res_scenario = default_attack_registry.get_scenario("ATK_RES_01")
    res_b_res, _, _ = engine.execute_scenario(
        scenario=res_scenario,
        baseline=BaselineSystemType.SYSTEM_B_STATIC_POLICY,
    )
    assert res_b_res.final_decision == "ALLOW"
    assert res_b_res.is_successful_attack is True


def test_comparative_baseline_system_c_policy_and_behavior():
    """Verifies System C: Catches behavioral sequence and burst anomalies in addition to static policy."""
    engine = AttackEngine()

    # Burst persistence attack
    per_scenario = default_attack_registry.get_scenario("ATK_PER_01")
    res_c_per, _, _ = engine.execute_scenario(
        scenario=per_scenario,
        baseline=BaselineSystemType.SYSTEM_C_POLICY_AND_BEHAVIOR,
    )
    assert res_c_per.final_decision in ["BLOCK", "DENY"]
    assert res_c_per.is_successful_attack is False


def test_comparative_baseline_system_d_full_agentsentinel():
    """Verifies System D (Full AgentSentinel): 100% prevention of dangerous adversarial actions."""
    engine = AttackEngine()

    dangerous_scenarios = [
        "ATK_CRED_01",  # Credential access
        "ATK_NET_01",   # Network abuse / IP literal
        "ATK_PROC_01",  # Unauthorized process execution
        "ATK_SBX_01",   # Subprocess in STRICT sandbox
        "ATK_OUT_01",   # Private key exfiltration
    ]

    for sid in dangerous_scenarios:
        scenario = default_attack_registry.get_scenario(sid)
        assert scenario is not None
        exec_res, findings, graph = engine.execute_scenario(
            scenario=scenario,
            baseline=BaselineSystemType.SYSTEM_D_FULL_AGENTSENTINEL,
        )
        assert exec_res.final_decision in ["BLOCK", "DENY"], f"Scenario {sid} was not blocked by System D"
        assert exec_res.is_successful_attack is False
        assert len(findings) >= 1
        assert len(graph.nodes) >= 1


# ============================================================================
# 6. BENIGN CONTROL SCENARIOS (FALSE POSITIVE SAFETY)
# ============================================================================

def test_benign_control_scenarios_allowed():
    """Verifies that legitimate benign control scenarios are safely allowed without false blocks."""
    engine = AttackEngine()
    benign_scenarios = ["CTL_BEN_01", "CTL_BEN_02", "CTL_BEN_03"]

    for sid in benign_scenarios:
        scenario = default_attack_registry.get_scenario(sid)
        assert scenario is not None
        exec_res, findings, graph = engine.execute_scenario(
            scenario=scenario,
            baseline=BaselineSystemType.SYSTEM_D_FULL_AGENTSENTINEL,
        )
        assert exec_res.final_decision == "ALLOW", f"Benign scenario {sid} was unexpectedly blocked"
        assert exec_res.is_successful_attack is True


# ============================================================================
# 7. MULTI-STEP ATTACK CHAINS & INTERRUPTION TRACKING
# ============================================================================

def test_multi_step_attack_chain_interruption():
    """Verifies that multi-step attacks track exact interrupted_at_step and halt subsequent execution."""
    chain_engine = AttackChainEngine()
    scenario = default_attack_registry.get_scenario("ATK_CHN_01")
    assert scenario is not None
    assert scenario.is_multi_step is True
    assert len(scenario.actions) == 3

    exec_res, findings, graph = chain_engine.execute_chain(
        scenario=scenario,
        baseline=BaselineSystemType.SYSTEM_D_FULL_AGENTSENTINEL,
    )

    # Step 1 is google_search (ALLOW), Step 2 is read_system_file (BLOCK)
    # The chain must be interrupted at step 2, and step 3 must never execute
    assert exec_res.interrupted_at_step == 2
    assert len(exec_res.step_results) == 2
    assert exec_res.step_results[0].decision == "ALLOW"
    assert exec_res.step_results[1].decision in ["BLOCK", "DENY"]
    assert exec_res.is_successful_attack is False


def test_rapid_persistence_chain_interruption():
    """Verifies ATK_PER_01 multi-step persistence probing is interrupted at step 1."""
    chain_engine = AttackChainEngine()
    scenario = default_attack_registry.get_scenario("ATK_PER_01")
    assert scenario is not None

    exec_res, findings, graph = chain_engine.execute_chain(
        scenario=scenario,
        baseline=BaselineSystemType.SYSTEM_D_FULL_AGENTSENTINEL,
    )
    assert exec_res.interrupted_at_step == 1
    assert len(exec_res.step_results) == 1
    assert exec_res.final_decision in ["BLOCK", "DENY"]


# ============================================================================
# 8. MULTI-AGENT DELEGATION ABUSE
# ============================================================================

def test_multi_agent_delegation_abuse_blocked():
    """Verifies that unauthorized or expired delegation attempts in multi-agent attacks are blocked."""
    engine = AttackEngine()

    # Expired delegation token
    del_scenario = default_attack_registry.get_scenario("ATK_DEL_02")
    assert del_scenario is not None
    exec_res, findings, _ = engine.execute_scenario(
        scenario=del_scenario,
        baseline=BaselineSystemType.SYSTEM_D_FULL_AGENTSENTINEL,
    )
    assert exec_res.final_decision in ["BLOCK", "DENY"]
    assert exec_res.is_successful_attack is False

    # Circular delegation
    circ_scenario = default_attack_registry.get_scenario("ATK_DEL_03")
    assert circ_scenario is not None
    exec_res_circ, _, _ = engine.execute_scenario(
        scenario=circ_scenario,
        baseline=BaselineSystemType.SYSTEM_D_FULL_AGENTSENTINEL,
    )
    assert exec_res_circ.final_decision in ["BLOCK", "DENY"]
    assert exec_res_circ.is_successful_attack is False


# ============================================================================
# 9. ATTACK GRAPH & THREAT FINDINGS VALIDATION
# ============================================================================

def test_attack_graph_and_findings_structure():
    """Verifies that attack execution generates valid AttackGraph and SecurityFinding structures."""
    engine = AttackEngine()
    scenario = default_attack_registry.get_scenario("ATK_NET_01")
    assert scenario is not None

    exec_res, findings, graph = engine.execute_scenario(
        scenario=scenario,
        baseline=BaselineSystemType.SYSTEM_D_FULL_AGENTSENTINEL,
    )

    # Check AttackGraph
    assert isinstance(graph, AttackGraph)
    assert len(graph.nodes) >= 2  # Start node + defense/step node
    assert len(graph.edges) >= 1

    # Check SecurityFindings
    assert len(findings) >= 1
    finding = findings[0]
    assert isinstance(finding, SecurityFinding)
    assert finding.scenario_id == "ATK_NET_01"
    assert finding.mitre_atlas_id.startswith("AML.T") or finding.mitre_atlas_id in ["UNMAPPED", "PENDING_VALIDATION"]
    assert finding.owasp_llm_category.startswith("LLM") or len(finding.owasp_llm_category) > 0
    assert len(finding.remediation) > 0


# ============================================================================
# 10. FAIL-CLOSED INVARIANTS & ZERO-BYPASS ENFORCEMENT
# ============================================================================

def test_fail_closed_on_corrupted_scenario():
    """Verifies that a corrupted or empty scenario fails closed without bypassing security."""
    engine = AttackEngine()
    corrupted_scenario = AttackScenario(
        scenario_id="ATK_CORRUPT_01",
        name="Corrupted Scenario",
        category=AttackCategory.TOOL_ABUSE,
        severity=AttackSeverity.CRITICAL,
        threat_objective=ThreatObjective.BYPASS_POLICY_DENY,
        description="Scenario with invalid empty actions",
        actions=[],
    )

    exec_res, findings, graph = engine.execute_scenario(
        scenario=corrupted_scenario,
        baseline=BaselineSystemType.SYSTEM_D_FULL_AGENTSENTINEL,
    )
    assert exec_res.final_decision in ["BLOCK", "DENY"]
    assert exec_res.is_successful_attack is False


def test_deterministic_replay():
    """Verifies that replaying a scenario yields identical verdicts and prevention stages."""
    engine = AttackEngine()
    scenario = default_attack_registry.get_scenario("ATK_PROC_01")
    assert scenario is not None

    res1, _, _ = engine.execute_scenario(scenario, baseline=BaselineSystemType.SYSTEM_D_FULL_AGENTSENTINEL)
    res2, _, _ = engine.execute_scenario(scenario, baseline=BaselineSystemType.SYSTEM_D_FULL_AGENTSENTINEL)

    assert res1.final_decision == res2.final_decision
    assert res1.is_successful_attack == res2.is_successful_attack
    assert res1.prevention_stage == res2.prevention_stage


# ============================================================================
# 11. COMPARATIVE BENCHMARK & CONTROL EFFECTIVENESS MATRIX
# ============================================================================

def test_comparative_benchmark_runner():
    """Verifies comparative benchmark execution across all 4 baselines on a subset of scenarios."""
    engine = AttackEngine()
    subset = [
        default_attack_registry.get_scenario("CTL_BEN_01"),
        default_attack_registry.get_scenario("ATK_CRED_01"),
    ]

    summary = engine.run_comparative_benchmark(
        scenarios=subset,
        baselines=[
            BaselineSystemType.SYSTEM_A_UNPROTECTED,
            BaselineSystemType.SYSTEM_B_STATIC_POLICY,
            BaselineSystemType.SYSTEM_C_POLICY_AND_BEHAVIOR,
            BaselineSystemType.SYSTEM_D_FULL_AGENTSENTINEL,
        ],
    )
    assert isinstance(summary, BenchmarkRunSummary)
    assert len(summary.baseline_summaries) == 4
    assert summary.total_scenarios_evaluated == 2


def test_control_effectiveness_matrix_evaluation():
    """Verifies generation of the 17-category control effectiveness matrix."""
    engine = AttackEngine()
    rows = engine.evaluate_control_effectiveness()
    assert len(rows) == 17

    for row in rows:
        assert isinstance(row, ControlEffectivenessRow)
        assert row.category in AttackCategory
        assert 0.0 <= row.coverage_rate <= 1.0
        assert len(row.primary_defense_control) > 0


# ============================================================================
# 12. DATABASE PERSISTENCE
# ============================================================================

def test_database_persistence_of_attack_runs(db_session):
    """Verifies that attack simulation runs and findings are persisted to PostgreSQL/SQLite."""
    engine = AttackEngine()
    scenario = default_attack_registry.get_scenario("ATK_CRED_01")
    assert scenario is not None

    exec_res, findings, _ = engine.execute_scenario(
        scenario=scenario,
        baseline=BaselineSystemType.SYSTEM_D_FULL_AGENTSENTINEL,
        db=db_session,
    )

    # Verify persisted run
    run_record = get_attack_run_by_id(db_session, exec_res.run_id)
    assert run_record is not None
    assert run_record.scenario_id == "ATK_CRED_01"
    assert run_record.final_decision in ["BLOCK", "DENY"]

    # Verify persisted findings
    persisted_findings = list_security_findings(db_session, run_id=exec_res.run_id)
    assert len(persisted_findings) >= 1
    assert persisted_findings[0].scenario_id == "ATK_CRED_01"


# ============================================================================
# 13. REST API ENDPOINTS
# ============================================================================

def test_api_list_attack_scenarios(client):
    """GET /api/v1/attacks returns scenario catalog with filtering."""
    # List all
    res = client.get("/api/v1/attacks")
    assert res.status_code == 200
    data = res.json()
    assert len(data) >= 25

    # Filter by category
    res_cat = client.get("/api/v1/attacks?category=CREDENTIAL_ACCESS")
    assert res_cat.status_code == 200
    cat_data = res_cat.json()
    assert len(cat_data) >= 1
    assert all(item["category"] == "CREDENTIAL_ACCESS" for item in cat_data)


def test_api_get_scenario_detail(client):
    """GET /api/v1/attacks/{scenario_id} returns scenario details."""
    res = client.get("/api/v1/attacks/ATK_CRED_01")
    assert res.status_code == 200
    data = res.json()
    assert data["scenario_id"] == "ATK_CRED_01"
    assert "actions" in data

    # 404 for missing scenario
    res_404 = client.get("/api/v1/attacks/NONEXISTENT_XYZ")
    assert res_404.status_code == 404


def test_api_run_attack_simulation(client):
    """POST /api/v1/attacks/run executes an attack scenario."""
    payload = {
        "scenario_id": "ATK_NET_01",
        "baseline_type": "SYSTEM_D_FULL_AGENTSENTINEL",
        "persist_to_db": False,
    }
    res = client.post("/api/v1/attacks/run", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "execution_result" in data
    assert "findings" in data
    assert "graph" in data
    assert data["execution_result"]["final_decision"] in ["BLOCK", "DENY"]


def test_api_replay_attack_simulation(client):
    """POST /api/v1/attacks/replay replays an attack scenario deterministically."""
    payload = {
        "scenario_id": "ATK_FS_01",
        "baseline_type": "SYSTEM_D_FULL_AGENTSENTINEL",
    }
    res = client.post("/api/v1/attacks/replay", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["execution_result"]["scenario_id"] == "ATK_FS_01"
    assert data["execution_result"]["final_decision"] in ["BLOCK", "DENY"]


def test_api_threat_findings_and_detail(client):
    """GET /api/v1/threats and GET /api/v1/threats/{finding_id}."""
    # First run a scenario to generate a finding
    run_res = client.post("/api/v1/attacks/run", json={
        "scenario_id": "ATK_CRED_01",
        "baseline_type": "SYSTEM_D_FULL_AGENTSENTINEL",
        "persist_to_db": True,
    })
    assert run_res.status_code == 200
    run_data = run_res.json()
    findings = run_data.get("findings", [])
    assert len(findings) >= 1
    finding_id = findings[0]["finding_id"]

    # List threats
    res_list = client.get("/api/v1/threats")
    assert res_list.status_code == 200
    threats = res_list.json()
    assert len(threats) >= 1

    # Get specific threat finding detail
    res_detail = client.get(f"/api/v1/threats/{finding_id}")
    assert res_detail.status_code == 200
    detail_data = res_detail.json()
    assert detail_data["finding_id"] == finding_id
    assert detail_data["scenario_id"] == "ATK_CRED_01"


def test_api_control_effectiveness(client):
    """GET /api/v1/security/control-effectiveness returns 17-category matrix."""
    res = client.get("/api/v1/security/control-effectiveness")
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 17
    categories = [item["category"] for item in data]
    assert "CREDENTIAL_ACCESS" in categories
    assert "DATA_EXFILTRATION" in categories


def test_api_run_benchmark(client):
    """POST /api/v1/benchmark/run and GET /api/v1/benchmark."""
    # Run benchmark for a specific category to keep test fast
    payload = {
        "category": "DESTRUCTIVE_INTENT",
        "baselines": [
            "SYSTEM_A_UNPROTECTED",
            "SYSTEM_D_FULL_AGENTSENTINEL",
        ],
        "persist_to_db": False,
    }
    res = client.post("/api/v1/benchmark/run", json=payload)
    assert res.status_code == 200
    summary = res.json()
    assert "benchmark_run_id" in summary
    assert len(summary["baseline_summaries"]) == 2

    # Query benchmark list
    res_list = client.get("/api/v1/benchmark")
    assert res_list.status_code == 200
    benchmarks = res_list.json()
    assert len(benchmarks) >= 1
