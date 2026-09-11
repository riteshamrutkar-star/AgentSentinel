"""
AgentSentinel Phase 0.6: Attack Simulation, Threat Intelligence & Security Validation Models.
Defines schemas for attack categories, scenarios, actions, execution results,
multi-step attack chains, graph representations, security findings, and benchmark runs.
"""

import uuid
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
from pydantic import BaseModel, Field

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AttackCategory(str, Enum):
    """The 17 canonical attack categories for AI agent security validation (A-Q)."""
    RECONNAISSANCE = "RECONNAISSANCE"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    SENSITIVE_DATA_ACCESS = "SENSITIVE_DATA_ACCESS"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    TOOL_ABUSE = "TOOL_ABUSE"
    FILESYSTEM_ABUSE = "FILESYSTEM_ABUSE"
    NETWORK_ABUSE = "NETWORK_ABUSE"
    PROCESS_ABUSE = "PROCESS_ABUSE"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    POLICY_MANIPULATION = "POLICY_MANIPULATION"
    DELEGATION_ABUSE = "DELEGATION_ABUSE"
    PRIVILEGE_LAUNDERING = "PRIVILEGE_LAUNDERING"
    PERSISTENCE_ATTEMPTS = "PERSISTENCE_ATTEMPTS"
    DESTRUCTIVE_INTENT = "DESTRUCTIVE_INTENT"
    RESOURCE_EXHAUSTION = "RESOURCE_EXHAUSTION"
    SANDBOX_VIOLATION = "SANDBOX_VIOLATION"


class AttackSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatObjective(str, Enum):
    EXFILTRATE_SSH_KEY = "EXFILTRATE_SSH_KEY"
    ACCESS_SYSTEM_SHADOW = "ACCESS_SYSTEM_SHADOW"
    DROP_DATABASE_SCHEMA = "DROP_DATABASE_SCHEMA"
    BYPASS_POLICY_DENY = "BYPASS_POLICY_DENY"
    LAUNDER_PRIVILEGES_ACROSS_AGENTS = "LAUNDER_PRIVILEGES_ACROSS_AGENTS"
    HIJACK_DELEGATION_TOKEN = "HIJACK_DELEGATION_TOKEN"
    EXHAUST_EXECUTION_TIMEOUT = "EXHAUST_EXECUTION_TIMEOUT"
    ESCAPE_FILESYSTEM_WORKSPACE = "ESCAPE_FILESYSTEM_WORKSPACE"
    ACCESS_CLOUD_METADATA = "ACCESS_CLOUD_METADATA"
    EGRESS_TO_EXFILTRATION_SINK = "EGRESS_TO_EXFILTRATION_SINK"
    EXECUTE_UNAUTHORIZED_BINARY = "EXECUTE_UNAUTHORIZED_BINARY"
    CHAIN_COMMAND_INJECTION = "CHAIN_COMMAND_INJECTION"
    INJECT_PROMPT_SYSTEM_OVERRIDE = "INJECT_PROMPT_SYSTEM_OVERRIDE"
    INJECT_PROMPT_TOOL_POLICY_BYPASS = "INJECT_PROMPT_TOOL_POLICY_BYPASS"
    REPEATED_ENDPOINT_HAMMERING = "REPEATED_ENDPOINT_HAMMERING"
    UNAUTHORIZED_TOOL_INVOCATION = "UNAUTHORIZED_TOOL_INVOCATION"
    STRICT_SANDBOX_ESCAPE = "STRICT_SANDBOX_ESCAPE"
    BENIGN_ROUTINE_TASK = "BENIGN_ROUTINE_TASK"


class BaselineSystemType(str, Enum):
    """The 4 comparative evaluation baselines."""
    SYSTEM_A_UNPROTECTED = "SYSTEM_A_UNPROTECTED"
    SYSTEM_B_STATIC_POLICY = "SYSTEM_B_STATIC_POLICY"
    SYSTEM_C_POLICY_AND_BEHAVIOR = "SYSTEM_C_POLICY_AND_BEHAVIOR"
    SYSTEM_D_FULL_AGENTSENTINEL = "SYSTEM_D_FULL_AGENTSENTINEL"


class AttackAction(BaseModel):
    """A discrete simulated step in an attack scenario or multi-step chain."""
    step_index: int = 1
    description: str
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    target_resource: str = ""
    agent_id: str
    agent_role: str = "default_agent"
    user_id: str = "eval_adversary"
    delegation_id: Optional[str] = None
    expected_step_decision: str = "BLOCK"  # ALLOW, BLOCK, REQUIRE_APPROVAL
    delay_ms: float = 0.0                  # Artificial velocity delay
    requested_profile: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AttackScenario(BaseModel):
    """Complete declarative definition of a controlled attack scenario."""
    scenario_id: str
    name: str
    category: AttackCategory
    description: str
    severity: AttackSeverity
    threat_objective: ThreatObjective
    is_adversarial: bool = True           # False for benign benchmark controls
    required_capabilities: List[str] = Field(default_factory=list)
    preconditions: Dict[str, Any] = Field(default_factory=dict)
    actions: List[AttackAction]
    expected_security_result: str = "BLOCK"  # Expected final AgentSentinel verdict
    safety_constraints: List[str] = Field(default_factory=list)
    evidence_requirements: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    version: str = "1.0.0"
    mitre_atlas_id: Optional[str] = None
    owasp_llm_id: Optional[str] = None
    is_multi_step: bool = False
    expected_primary_detector: str = "POLICY_ENGINE"

    def model_post_init(self, __context):
        if not self.is_multi_step:
            self.is_multi_step = len(self.actions) > 1
        if not self.mitre_atlas_id or not self.owasp_llm_id:
            from app.attack.taxonomy import get_taxonomy_entry
            entry = get_taxonomy_entry(self.category)
            if entry:
                if not self.mitre_atlas_id:
                    self.mitre_atlas_id = entry.mitre_atlas_id
                if not self.owasp_llm_id:
                    self.owasp_llm_id = entry.owasp_llm_category

    @property
    def objective(self) -> str:
        return self.threat_objective.value if hasattr(self.threat_objective, 'value') else str(self.threat_objective)


class AttackStepResult(BaseModel):
    """Outcome and telemetry for a single action step in an attack simulation."""
    step_index: int
    tool_name: str
    target_resource: str
    agent_id: str
    policy_verdict: str                  # ALLOW, DENY, REQUIRE_APPROVAL
    behavioral_score: float = 0.0        # 0.0 to 1.0
    unified_risk_score: float = 0.0      # Alias for behavioral_score
    behavioral_triggered: bool = False   # score >= 0.65
    multiagent_verdict: str = "N/A"      # ALLOW, BLOCK, N/A
    execution_status: str = "NOT_REACHED" # COMPLETED, BLOCKED, PENDING_APPROVAL, NOT_REACHED
    execution_error: Optional[str] = None
    final_verdict: str                   # ALLOW, BLOCK, REQUIRE_APPROVAL
    execution_allowed: bool = False
    primary_control_detected: str = "NONE" # POLICY, BEHAVIORAL, MULTIAGENT, EXECUTION_GATEWAY, NONE
    latency_ms: float = 0.0
    evidence: str = ""
    passed_expectation: bool = False

    def model_post_init(self, __context):
        if not self.unified_risk_score and self.behavioral_score:
            self.unified_risk_score = self.behavioral_score
        elif not self.behavioral_score and self.unified_risk_score:
            self.behavioral_score = self.unified_risk_score

    @property
    def decision(self) -> str:
        return self.final_verdict


class AttackExecutionResult(BaseModel):
    """Consolidated outcome of running an AttackScenario."""
    scenario_id: str
    run_id: str
    baseline_type: BaselineSystemType
    status: str = "COMPLETED"            # COMPLETED, INTERRUPTED, ERROR
    total_steps: int
    completed_steps: int
    interrupted_at_step: Optional[int] = None
    is_interrupted: bool = False
    step_results: List[AttackStepResult] = Field(default_factory=list)
    final_decision: str = "BLOCK"
    execution_allowed: bool = False
    primary_control: str = "NONE"
    prevention_stage: str = "NONE"
    is_successful_attack: bool = False
    total_latency_ms: float = 0.0
    passed: bool = False
    created_at: datetime = Field(default_factory=utc_now)

    def model_post_init(self, __context):
        if not self.prevention_stage and self.primary_control:
            self.prevention_stage = self.primary_control
        elif not self.primary_control and self.prevention_stage:
            self.primary_control = self.prevention_stage
        if self.final_decision == "ALLOW" and self.execution_allowed:
            self.is_successful_attack = True


class AttackChain(BaseModel):
    """An ordered multi-step chain representing progressive multi-stage attack behavior."""
    chain_id: str
    name: str
    description: str
    category: AttackCategory
    severity: AttackSeverity
    actions: List[AttackAction]
    session_id: str = Field(default_factory=lambda: f"sess_chain_{uuid.uuid4().hex[:8]}")
    expected_interrupt_step: int = 1     # Which step is expected to be halted by defense


class AttackGraphNode(BaseModel):
    """A node in an attack graph representing an entity or security event."""
    id: str
    node_type: str  # Agent, Tool, Resource, Action, Decision, Event, Execution
    label: str
    properties: Dict[str, Any] = Field(default_factory=dict)


class AttackGraphEdge(BaseModel):
    """A directed edge in an attack graph representing an interaction or causal relationship."""
    source_id: str
    target_id: str
    relationship: str  # DELEGATES_TO, INVOKES, ACCESSES, PRODUCES_EVENT, EVALUATED_AS, ENFORCES_DECISION
    properties: Dict[str, Any] = Field(default_factory=dict)


class AttackGraph(BaseModel):
    """Structured graph data model for visual and programmatic attack trace representation."""
    graph_id: str
    scenario_id: str
    run_id: str
    nodes: List[AttackGraphNode] = Field(default_factory=list)
    edges: List[AttackGraphEdge] = Field(default_factory=list)


class SecurityFinding(BaseModel):
    """Formal security finding generated when an attack is observed or blocked."""
    finding_id: str = Field(default_factory=lambda: f"fnd_{uuid.uuid4().hex[:10]}")
    run_id: str
    scenario_id: str
    category: AttackCategory
    severity: AttackSeverity
    title: str
    affected_agent_id: str = "eval_worker"
    affected_tool: str = ""
    affected_resource: str = ""
    policy_result: str = "DENY"
    behavioral_result: str = "N/A"
    execution_result: str = "BLOCKED"
    final_decision: str = "BLOCK"
    primary_control: str = "POLICY_ENGINE"
    prevented_by: str = "POLICY_ENGINE"
    evidence: Any = ""
    explanation: str = ""
    description: str = ""
    mitre_atlas_id: Optional[str] = None
    mitre_atlas_technique: Optional[str] = None
    owasp_llm_id: Optional[str] = None
    owasp_llm_category: Optional[str] = None
    remediation: str = ""
    created_at: datetime = Field(default_factory=utc_now)

    def model_post_init(self, __context):
        if not self.description and self.explanation:
            self.description = self.explanation
        elif not self.explanation and self.description:
            self.explanation = self.description
        if not self.prevented_by and self.primary_control:
            self.prevented_by = self.primary_control
        elif not self.primary_control and self.prevented_by:
            self.primary_control = self.prevented_by


class ControlEffectivenessRow(BaseModel):
    """Row in the Control Effectiveness Matrix."""
    category: AttackCategory
    total_attacks: int = 0
    policy_blocks: int = 0
    behavioral_detections: int = 0
    multiagent_blocks: int = 0
    execution_blocks: int = 0
    final_blocks: int = 0
    final_approvals: int = 0
    final_allows: int = 0
    detection_rate: float = 0.0
    primary_control: str = "POLICY_ENGINE"
    unprotected_allowed_pct: float = 100.0
    static_policy_block_pct: float = 0.0
    behavioral_block_pct: float = 0.0
    full_sentinel_block_pct: float = 100.0

    @property
    def coverage_rate(self) -> float:
        return round(self.full_sentinel_block_pct / 100.0, 4)

    @property
    def primary_defense_control(self) -> str:
        return self.primary_control


class BenchmarkRunSummary(BaseModel):
    """Summary of a full benchmark evaluation run across multiple scenarios and baselines."""
    run_id: str = Field(default_factory=lambda: f"bench_{uuid.uuid4().hex[:8]}")
    benchmark_run_id: str = Field(default="")
    timestamp: datetime = Field(default_factory=utc_now)
    total_scenarios_evaluated: int = 0
    total_scenarios: int = 0
    baselines_evaluated: List[str] = Field(default_factory=list)
    baseline_summaries: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    baseline_metrics: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    confusion_matrix: Dict[str, int] = Field(default_factory=dict)
    category_detection_rates: Dict[str, float] = Field(default_factory=dict)
    control_effectiveness_matrix: List[ControlEffectivenessRow] = Field(default_factory=list)
    mean_latency_ms: float = 0.0
    overall_f1: float = 0.0
    f1_score: float = 0.0
    overall_accuracy: float = 0.0
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    adversarial_prevention_rate: float = 0.0
    benign_false_positive_rate: float = 0.0

