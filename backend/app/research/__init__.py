"""
AgentSentinel Phase 0.7: Research Package Init.
Exports core domain models, execution engines, dataset generators, statistical analyzers,
reproducibility managers, ablation engines, and reporting tools.
"""

from app.research.models import (
    SystemVariant,
    SystemVariantConfig,
    DatasetSplit,
    AttackComplexity,
    ControlAttribution,
    ExperimentScenario,
    ScenarioObservation,
    MetricResult,
    StatisticalComparison,
    AblationResult,
    ErrorAnalysisRecord,
    ReproducibilityManifest,
    ExperimentConfiguration,
    Experiment,
    ExperimentRun,
    ResearchArtifact,
    utc_now,
)
from app.research.baselines import (
    SYSTEM_CONFIGS,
    get_system_config,
    SystemVariantExecutor,
)
from app.research.dataset import ResearchDataset
from app.research.generator import ResearchDatasetGenerator
from app.research.statistics import StatisticalAnalyzer
from app.research.metrics import ResearchMetricsCalculator
from app.research.reproducibility import ReproducibilityManager
from app.research.ablation import AblationStudyEngine
from app.research.runner import ExperimentRunner
from app.research.registry import ExperimentRegistry, default_experiment_registry
from app.research.reports import ResearchReportGenerator
from app.research.export import ResearchExporter

__all__ = [
    "SystemVariant",
    "SystemVariantConfig",
    "DatasetSplit",
    "AttackComplexity",
    "ControlAttribution",
    "ExperimentScenario",
    "ScenarioObservation",
    "MetricResult",
    "StatisticalComparison",
    "AblationResult",
    "ErrorAnalysisRecord",
    "ReproducibilityManifest",
    "ExperimentConfiguration",
    "Experiment",
    "ExperimentRun",
    "ResearchArtifact",
    "utc_now",
    "SYSTEM_CONFIGS",
    "get_system_config",
    "SystemVariantExecutor",
    "ResearchDataset",
    "ResearchDatasetGenerator",
    "StatisticalAnalyzer",
    "ResearchMetricsCalculator",
    "ReproducibilityManager",
    "AblationStudyEngine",
    "ExperimentRunner",
    "ExperimentRegistry",
    "default_experiment_registry",
    "ResearchReportGenerator",
    "ResearchExporter",
]
