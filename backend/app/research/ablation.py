"""
AgentSentinel Phase 0.7: Ablation Study Engine.
Quantifies the individual defensive contribution and necessity of each security layer:
Behavioral Risk Intelligence, Multi-Agent Governance, Sandboxing/Isolation, and Approvals.
Computes precise performance deltas (F1 delta, Detection Rate delta, Latency delta).
"""

from typing import Dict, List, Optional
from sqlalchemy.orm import Session

from app.research.models import (
    SystemVariant,
    ExperimentScenario,
    ExperimentRun,
    AblationResult,
    MetricResult,
)
from app.research.baselines import get_system_config, SystemVariantExecutor
from app.research.dataset import ResearchDataset
from app.research.metrics import ResearchMetricsCalculator


class AblationStudyEngine:
    """
    Executes formal ablation experiments across the 4 ablation variants
    and computes performance degradation metrics against the full defense-in-depth system.
    """

    ABLATION_VARIANTS = [
        (SystemVariant.ABLATION_NO_BEHAVIOR, "Behavioral Risk Intelligence (Unified Risk Engine)"),
        (SystemVariant.ABLATION_NO_MULTIAGENT, "Multi-Agent Governance (Delegation Interceptor)"),
        (SystemVariant.ABLATION_NO_SANDBOX, "Sandboxing & Container Isolation (Execution Gateway)"),
        (SystemVariant.ABLATION_NO_APPROVAL, "Human Authorization & Approval Escalation"),
    ]

    @classmethod
    def evaluate_ablation(
        cls,
        variant: SystemVariant,
        removed_layer_name: str,
        scenarios: List[ExperimentScenario],
        full_metrics: MetricResult,
        experiment_id: str,
        seed: int = 42,
        db: Optional[Session] = None,
    ) -> AblationResult:
        """
        Execute scenarios under an ablation configuration and compare with full system metrics.
        """
        cfg = get_system_config(variant)
        executor = SystemVariantExecutor(config=cfg)
        run_id = f"run_{experiment_id}_{variant.value.lower()}"

        observations = []
        for sc in scenarios:
            obs, _ = executor.execute_scenario(
                scenario=sc,
                experiment_id=experiment_id,
                run_id=run_id,
                trial_index=1,
                db=db,
            )
            observations.append(obs)

        ablation_metrics = ResearchMetricsCalculator.compute_metrics(
            observations=observations,
            baseline_latency_ms=0.0,
            seed=seed,
        )

        f1_delta = round(ablation_metrics.f1_score - full_metrics.f1_score, 4)
        dr_delta = round(ablation_metrics.detection_rate - full_metrics.detection_rate, 4)
        lat_delta = round(ablation_metrics.latency_median_ms - full_metrics.latency_median_ms, 2)

        # Generate explanatory summary
        if dr_delta < 0:
            summary = (
                f"Removing {removed_layer_name} reduces detection rate by {abs(dr_delta)*100:.1f}% "
                f"and F1 score by {abs(f1_delta):.4f}. Median latency shifted by {lat_delta:+.2f} ms."
            )
        else:
            summary = (
                f"Removing {removed_layer_name} had minimal impact on static detection rate, "
                f"with latency shifting by {lat_delta:+.2f} ms."
            )

        return AblationResult(
            ablation_variant=variant,
            removed_layer=removed_layer_name,
            f1_score=ablation_metrics.f1_score,
            f1_delta_vs_full=f1_delta,
            detection_rate=ablation_metrics.detection_rate,
            detection_rate_delta=dr_delta,
            fpr=ablation_metrics.false_positive_rate,
            latency_ms=ablation_metrics.latency_median_ms,
            latency_delta_ms=lat_delta,
            degradation_summary=summary,
        )

    @classmethod
    def run_ablation_study(
        cls,
        scenarios: List[ExperimentScenario],
        full_system_run: ExperimentRun,
        experiment_id: str,
        seed: int = 42,
        db: Optional[Session] = None,
    ) -> List[AblationResult]:
        """
        Run the complete ablation suite against all 4 ablation variants.
        """
        if not full_system_run.metrics:
            raise ValueError("Full system run must have computed metrics to perform ablation study.")

        full_metrics = full_system_run.metrics
        results: List[AblationResult] = []

        for var, layer_name in cls.ABLATION_VARIANTS:
            res = cls.evaluate_ablation(
                variant=var,
                removed_layer_name=layer_name,
                scenarios=scenarios,
                full_metrics=full_metrics,
                experiment_id=experiment_id,
                seed=seed,
                db=db,
            )
            results.append(res)

        return results
