"""
AgentSentinel Phase 0.7: Experiment Runner Engine.
Coordinates multi-trial experimental runs across configured system variants and dataset splits.
Captures raw observations, computes metrics, generates reproducibility manifests,
and records structured error analysis records.
"""

import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.core.logger import logger
from app.research.models import (
    SystemVariant,
    ExperimentScenario,
    ScenarioObservation,
    MetricResult,
    StatisticalComparison,
    ErrorAnalysisRecord,
    ExperimentConfiguration,
    Experiment,
    ExperimentRun,
    DatasetSplit,
    utc_now,
)
from app.research.baselines import get_system_config, SystemVariantExecutor
from app.research.dataset import ResearchDataset
from app.research.metrics import ResearchMetricsCalculator
from app.research.statistics import StatisticalAnalyzer
from app.research.reproducibility import ReproducibilityManager


class ExperimentRunner:
    """
    Executes rigorous comparative security experiments across System Variants (A, B, C, D)
    and produces fully traceable, publication-ready results.
    """

    def __init__(self, dataset: ResearchDataset):
        self.dataset = dataset

    def run_experiment(
        self,
        config: ExperimentConfiguration,
        db: Optional[Session] = None,
    ) -> Tuple[Experiment, List[ExperimentRun], List[StatisticalComparison]]:
        """
        Execute an experiment across all specified system variants and repetitions.
        Returns the Experiment, List of ExperimentRun results, and pairwise StatisticalComparisons.
        """
        exp_id = f"exp_{uuid.uuid4().hex[:8]}"
        experiment = Experiment(
            experiment_id=exp_id,
            name=config.experiment_name,
            description=config.description,
            hypothesis="Full AgentSentinel (System D) significantly outperforms baselines A, B, C in F1 and detection rate.",
            config=config,
            created_at=utc_now(),
            status="RUNNING",
        )

        # Filter scenarios by requested split
        scenarios = self.dataset.get_split(config.split)
        if not scenarios:
            scenarios = self.dataset.scenarios

        runs: List[ExperimentRun] = []
        run_observations_map: Dict[SystemVariant, List[ScenarioObservation]] = {}
        baseline_latency = 0.0

        for variant in config.variants:
            run_id = f"run_{exp_id}_{variant.value.lower()}"
            experiment.runs.append(run_id)

            cfg = get_system_config(variant)
            executor = SystemVariantExecutor(config=cfg)

            all_observations: List[ScenarioObservation] = []
            error_records: List[ErrorAnalysisRecord] = []
            run_start = time.perf_counter()

            for rep in range(1, config.repetitions + 1):
                for sc in scenarios:
                    obs, err = executor.execute_scenario(
                        scenario=sc,
                        experiment_id=exp_id,
                        run_id=run_id,
                        trial_index=rep,
                        db=db,
                    )
                    all_observations.append(obs)
                    if err:
                        error_records.append(err)

            run_duration_ms = round((time.perf_counter() - run_start) * 1000, 2)
            run_observations_map[variant] = all_observations

            # If this is System A, use its median latency as the baseline latency for overhead calculations
            if variant == SystemVariant.SYSTEM_A_UNPROTECTED and all_observations:
                baseline_latency = round(
                    float(sorted([o.latency_ms for o in all_observations])[len(all_observations) // 2]), 2
                )

            # Compute metrics
            metrics = ResearchMetricsCalculator.compute_metrics(
                observations=all_observations,
                baseline_latency_ms=baseline_latency,
                seed=config.seed,
            )
            cat_metrics = ResearchMetricsCalculator.compute_category_metrics(
                observations=all_observations, seed=config.seed
            )
            cplx_metrics = ResearchMetricsCalculator.compute_complexity_metrics(
                observations=all_observations, seed=config.seed
            )
            attribution = ResearchMetricsCalculator.compute_control_attribution(all_observations)

            # Generate Reproducibility Manifest
            manifest = ReproducibilityManager.create_manifest(
                experiment_id=exp_id,
                run_id=run_id,
                dataset_id=self.dataset.dataset_id,
                dataset_version=self.dataset.version,
                dataset_hash=self.dataset.sha256_hash or self.dataset.compute_sha256(),
                seed=config.seed,
                total_scenarios=len(scenarios),
            )

            exp_run = ExperimentRun(
                run_id=run_id,
                experiment_id=exp_id,
                variant=variant,
                seed=config.seed,
                repetitions=config.repetitions,
                total_scenarios=len(scenarios),
                total_observations=len(all_observations),
                status="COMPLETED",
                execution_time_ms=run_duration_ms,
                metrics=metrics,
                category_metrics=cat_metrics,
                complexity_metrics=cplx_metrics,
                control_attribution=attribution,
                manifest=manifest,
                error_records=error_records,
                created_at=utc_now(),
            )
            runs.append(exp_run)

            # Persist to database if session provided
            if db:
                try:
                    from app.db.crud import (
                        record_research_experiment,
                        record_research_run,
                        record_research_observation,
                    )
                    record_research_experiment(
                        db=db,
                        experiment_id=exp_id,
                        name=experiment.name,
                        description=experiment.description,
                        dataset_id=config.dataset_id,
                        config=config.model_dump() if hasattr(config, "model_dump") else config.dict(),
                    )
                    record_research_run(
                        db=db,
                        run_id=run_id,
                        experiment_id=exp_id,
                        variant=variant.value,
                        seed=config.seed,
                        total_scenarios=len(scenarios),
                        total_observations=len(all_observations),
                        f1_score=metrics.f1_score,
                        precision=metrics.precision,
                        recall=metrics.recall,
                        detection_rate=metrics.detection_rate,
                        fpr=metrics.false_positive_rate,
                        latency_median_ms=metrics.latency_median_ms,
                        execution_time_ms=run_duration_ms,
                        metrics_summary=metrics.model_dump() if hasattr(metrics, "model_dump") else metrics.dict(),
                        manifest=manifest.model_dump() if hasattr(manifest, "model_dump") else manifest.dict(),
                    )
                    for obs in all_observations:
                        record_research_observation(
                            db=db,
                            observation_id=obs.observation_id,
                            experiment_id=exp_id,
                            run_id=run_id,
                            scenario_id=obs.scenario_id,
                            variant=obs.system_variant.value,
                            expected_outcome=obs.expected_outcome,
                            actual_outcome=obs.actual_outcome,
                            attribution=obs.attribution.value,
                            latency_ms=obs.latency_ms,
                            passed=obs.passed,
                        )
                except Exception as exc:
                    logger.error(f"Failed to persist research run to database: {exc}", exc_info=True)

        experiment.status = "COMPLETED"

        # Pairwise Statistical Comparisons: System D vs (A, B, C)
        comparisons: List[StatisticalComparison] = []
        if SystemVariant.SYSTEM_D_FULL_AGENTSENTINEL in run_observations_map:
            obs_d = run_observations_map[SystemVariant.SYSTEM_D_FULL_AGENTSENTINEL]
            lat_d = [o.latency_ms for o in obs_d]
            acc_d = [1.0 if o.passed else 0.0 for o in obs_d]

            for baseline_var in (
                SystemVariant.SYSTEM_A_UNPROTECTED,
                SystemVariant.SYSTEM_B_STATIC_POLICY,
                SystemVariant.SYSTEM_C_POLICY_AND_BEHAVIOR,
            ):
                if baseline_var in run_observations_map:
                    obs_base = run_observations_map[baseline_var]
                    lat_base = [o.latency_ms for o in obs_base]
                    acc_base = [1.0 if o.passed else 0.0 for o in obs_base]

                    # Accuracy / Security Performance comparison
                    cmp_acc = StatisticalAnalyzer.compare_variants(
                        variant_a=baseline_var,
                        variant_b=SystemVariant.SYSTEM_D_FULL_AGENTSENTINEL,
                        values_a=acc_base,
                        values_b=acc_d,
                        metric_name="accuracy",
                        higher_is_better=True,
                        seed=config.seed,
                    )
                    comparisons.append(cmp_acc)

                    # Latency comparison (lower is better)
                    cmp_lat = StatisticalAnalyzer.compare_variants(
                        variant_a=baseline_var,
                        variant_b=SystemVariant.SYSTEM_D_FULL_AGENTSENTINEL,
                        values_a=lat_base,
                        values_b=lat_d,
                        metric_name="latency_ms",
                        higher_is_better=False,
                        seed=config.seed,
                    )
                    comparisons.append(cmp_lat)

        return experiment, runs, comparisons
