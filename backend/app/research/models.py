"""
AgentSentinel Phase 0.7: Research Domain Models & Schemas.
Formalizes first-class experimental entities, system variants, observation tracking,
reproducibility manifests, statistical comparisons, ablation results, and error classifications.
"""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.attack.models import AttackCategory, AttackSeverity

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# --- Enums ---

class SystemVariant(str, Enum):
    """Comparative architectural baselines and formal ablation variants."""
    SYSTEM_A_UNPROTECTED = "SYSTEM_A_UNPROTECTED"
    SYSTEM_B_STATIC_POLICY = "SYSTEM_B_STATIC_POLICY"
    SYSTEM_C_POLICY_AND_BEHAVIOR = "SYSTEM_C_POLICY_AND_BEHAVIOR"
    SYSTEM_D_FULL_AGENTSENTINEL = "SYSTEM_D_FULL_AGENTSENTINEL"
    # Ablation Variants
    ABLATION_NO_BEHAVIOR = "ABLATION_NO_BEHAVIOR"
    ABLATION_NO_MULTIAGENT = "ABLATION_NO_MULTIAGENT"
    ABLATION_NO_SANDBOX = "ABLATION_NO_SANDBOX"
    ABLATION_NO_APPROVAL = "ABLATION_NO_APPROVAL"


class DatasetSplit(str, Enum):
    """Dataset partition splits for reproducible research."""
    TRAIN = "TRAIN"
    VALIDATION = "VALIDATION"
    TEST = "TEST"
    ALL = "ALL"


class AttackComplexity(str, Enum):
    """Graduated complexity levels for adversarial scenarios."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    MULTI_STEP = "MULTI_STEP"


class ControlAttribution(str, Enum):
    """Causal attribution identifying which specific control intercepted the attack."""
    POLICY = "POLICY"
    BEHAVIOR = "BEHAVIOR"
    MULTI_AGENT = "MULTI_AGENT"
    EXECUTION_GATEWAY = "EXECUTION_GATEWAY"
    APPROVAL = "APPROVAL"
    MULTIPLE_CONTROLS = "MULTIPLE_CONTROLS"
    MISSED = "MISSED"


# --- System Configuration ---

class SystemVariantConfig(BaseModel):
    """Explicit declaration of enabled defensive layers for a system variant."""
    variant: SystemVariant
    policy_enabled: bool
    behavioral_enabled: bool
    multiagent_enabled: bool
    execution_gateway_enabled: bool
    approval_enabled: bool
    sandboxing_enabled: bool
    description: str


# --- Dataset Models ---

class ExperimentScenario(BaseModel):
    """Formalized scenario representation within a research dataset."""
    scenario_id: str
    scenario_version: str = "1.0.0"
    base_scenario_id: str = ""  # Base ID to prevent train/val/test group leakage
    name: str
    category: AttackCategory
    severity: AttackSeverity
    complexity: AttackComplexity = AttackComplexity.LOW
    threat_objective: str = ""
    is_adversarial: bool = True
    is_multi_step: bool = False
    actions: List[Dict[str, Any]] = Field(default_factory=list)
    expected_decision: str = "BLOCK"
    expected_primary_detector: str = "POLICY_ENGINE"
    mitre_atlas_id: str = "UNMAPPED"
    owasp_llm_id: str = "UNMAPPED"
    split: DatasetSplit = DatasetSplit.ALL
    metadata: Dict[str, Any] = Field(default_factory=dict)


# --- Raw Observation Model ---

class ScenarioObservation(BaseModel):
    """Raw, granular observation for a single scenario execution trial."""
    observation_id: str = Field(default_factory=lambda: f"obs_{uuid.uuid4().hex[:10]}")
    experiment_id: str
    run_id: str
    scenario_id: str
    scenario_version: str = "1.0.0"
    trial_index: int = 1
    system_variant: SystemVariant
    category: str
    severity: str
    complexity: str
    expected_outcome: str
    actual_outcome: str
    policy_result: str = "ALLOW"
    behavioral_result: str = "N/A"
    behavioral_score: float = 0.0
    multi_agent_result: str = "N/A"
    execution_result: str = "NOT_REACHED"
    final_decision: str = "ALLOW"
    attribution: ControlAttribution = ControlAttribution.MISSED
    evidence: str = ""
    latency_ms: float = 0.0
    interrupted_at_step: Optional[int] = None
    passed: bool = True
    timestamp: datetime = Field(default_factory=utc_now)


# --- Metric & Statistical Models ---

class MetricResult(BaseModel):
    """Rigorous classification and performance metrics computed over observations."""
    total_observations: int = 0
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    accuracy: float = 0.0
    false_positive_rate: float = 0.0
    false_negative_rate: float = 0.0
    detection_rate: float = 0.0
    block_rate: float = 0.0
    approval_rate: float = 0.0
    chain_interruption_rate: float = 0.0

    # Latency percentiles & dispersion
    latency_mean_ms: float = 0.0
    latency_median_ms: float = 0.0
    latency_p95_ms: float = 0.0
    latency_p99_ms: float = 0.0
    latency_std_ms: float = 0.0
    latency_min_ms: float = 0.0
    latency_max_ms: float = 0.0
    security_overhead_ms: float = 0.0

    # 95% Confidence Intervals (Bootstrap)
    ci_f1_lower: Optional[float] = None
    ci_f1_upper: Optional[float] = None
    ci_latency_lower: Optional[float] = None
    ci_latency_upper: Optional[float] = None


class StatisticalComparison(BaseModel):
    """Pairwise statistical comparison between two system variants."""
    comparison_id: str = Field(default_factory=lambda: f"cmp_{uuid.uuid4().hex[:8]}")
    variant_a: SystemVariant
    variant_b: SystemVariant
    metric_name: str
    mean_a: float
    mean_b: float
    mean_diff: float
    cohens_d: float = 0.0
    ci_lower: float = 0.0
    ci_upper: float = 0.0
    p_value: Optional[float] = None
    conclusion: str = "INCONCLUSIVE"  # SIGNIFICANT_IMPROVEMENT, SIGNIFICANT_DEGRADATION, NO_DIFFERENCE, INCONCLUSIVE


class AblationResult(BaseModel):
    """Measured impact when a specific defensive layer is removed."""
    ablation_variant: SystemVariant
    removed_layer: str
    f1_score: float
    f1_delta_vs_full: float
    detection_rate: float
    detection_rate_delta: float
    fpr: float
    latency_ms: float
    latency_delta_ms: float
    degradation_summary: str


# --- Error Analysis Record ---

class ErrorAnalysisRecord(BaseModel):
    """Structured record for False Positives, False Negatives, and unexpected decisions."""
    error_id: str = Field(default_factory=lambda: f"err_{uuid.uuid4().hex[:8]}")
    experiment_id: str
    run_id: str
    scenario_id: str
    system_variant: SystemVariant
    error_type: str  # FALSE_POSITIVE, FALSE_NEGATIVE, UNEXPECTED_APPROVAL, UNEXPECTED_BLOCK
    expected_decision: str
    actual_decision: str
    control_layer_involved: str
    detector_scores: Dict[str, Any] = Field(default_factory=dict)
    evidence: str = ""
    probable_cause: str = "UNKNOWN"  # POLICY, BEHAVIOR, MULTI_AGENT, EXECUTION, DATASET, SCENARIO, UNKNOWN
    notes: str = ""


# --- Reproducibility Manifest ---

class ReproducibilityManifest(BaseModel):
    """Immutable environment and configuration manifest ensuring experimental repeatability."""
    manifest_id: str = Field(default_factory=lambda: f"man_{uuid.uuid4().hex[:8]}")
    experiment_id: str
    run_id: str
    timestamp: datetime = Field(default_factory=utc_now)
    software_version: str = "0.7.0"
    git_commit: str = "HEAD"
    python_version: str = ""
    os_platform: str = ""
    db_engine: str = "PostgreSQL 17"
    config_hash: str = ""
    detector_weights: Dict[str, float] = Field(default_factory=dict)
    thresholds: Dict[str, float] = Field(default_factory=dict)
    dataset_id: str = "dataset-v1.0"
    dataset_version: str = "1.0.0"
    dataset_hash: str = ""
    seed: int = 42
    total_scenarios: int = 0


# --- Experiment & Run Models ---

class ExperimentConfiguration(BaseModel):
    """Specification of an experimental study."""
    experiment_name: str
    description: str = ""
    dataset_id: str = "dataset-v1.0"
    dataset_version: str = "1.0.0"
    variants: List[SystemVariant] = Field(
        default_factory=lambda: [
            SystemVariant.SYSTEM_A_UNPROTECTED,
            SystemVariant.SYSTEM_B_STATIC_POLICY,
            SystemVariant.SYSTEM_C_POLICY_AND_BEHAVIOR,
            SystemVariant.SYSTEM_D_FULL_AGENTSENTINEL,
        ]
    )
    repetitions: int = 1
    seed: int = 42
    split: DatasetSplit = DatasetSplit.ALL
    timeout_seconds: float = 30.0


class Experiment(BaseModel):
    """High-level research investigation uniting hypothesis, configuration, and runs."""
    experiment_id: str = Field(default_factory=lambda: f"exp_{uuid.uuid4().hex[:8]}")
    name: str
    description: str = ""
    hypothesis: str = ""
    config: ExperimentConfiguration
    runs: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    status: str = "CREATED"  # CREATED, RUNNING, COMPLETED, FAILED


class ExperimentRun(BaseModel):
    """Execution trial instance under a specific variant, seed, and repetition count."""
    run_id: str = Field(default_factory=lambda: f"run_exp_{uuid.uuid4().hex[:8]}")
    experiment_id: str
    variant: SystemVariant
    seed: int = 42
    repetitions: int = 1
    total_scenarios: int = 0
    total_observations: int = 0
    status: str = "COMPLETED"  # RUNNING, COMPLETED, FAILED
    execution_time_ms: float = 0.0
    metrics: Optional[MetricResult] = None
    category_metrics: Dict[str, MetricResult] = Field(default_factory=dict)
    complexity_metrics: Dict[str, MetricResult] = Field(default_factory=dict)
    control_attribution: Dict[str, int] = Field(default_factory=dict)
    manifest: Optional[ReproducibilityManifest] = None
    error_records: List[ErrorAnalysisRecord] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)


class ResearchArtifact(BaseModel):
    """Descriptor for exported research evidence files."""
    artifact_id: str = Field(default_factory=lambda: f"art_{uuid.uuid4().hex[:8]}")
    run_id: str
    experiment_id: str
    artifact_type: str  # DATASET, REPORT_MD, REPORT_JSON, MANIFEST, TABLE, FIGURE
    filename: str
    file_path: str
    file_format: str  # JSON, JSONL, CSV, MD, SVG
    sha256_hash: str
    size_bytes: int = 0
    created_at: datetime = Field(default_factory=utc_now)
