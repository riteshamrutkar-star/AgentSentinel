"""
AgentSentinel Phase 0.7: Research Metrics Engine.
Computes mathematically rigorous classification metrics, latency distributions,
category breakdowns, complexity scalings, and causal control attributions.
Strictly adheres to empirical accountability: every metric has a traceable denominator
computed directly from raw observations.
"""

import math
import statistics
from typing import Dict, List, Optional

from app.research.models import (
    ScenarioObservation,
    MetricResult,
    ControlAttribution,
)
from app.research.statistics import StatisticalAnalyzer


class ResearchMetricsCalculator:
    """
    Computes publication-grade security metrics and statistical intervals
    from raw ScenarioObservation collections.
    """

    @classmethod
    def compute_metrics(
        cls,
        observations: List[ScenarioObservation],
        baseline_latency_ms: float = 0.0,
        seed: int = 42,
    ) -> MetricResult:
        """
        Compute comprehensive classification, detection, and latency metrics
        from raw trial observations.
        """
        if not observations:
            return MetricResult()

        total = len(observations)
        tp = 0
        fp = 0
        tn = 0
        fn = 0
        blocks = 0
        approvals = 0
        interrupted_count = 0
        multi_step_attack_count = 0
        latencies: List[float] = []
        f1_binary_samples: List[float] = []

        for obs in observations:
            latencies.append(obs.latency_ms)

            # Ground truth: Expected decision
            is_adversarial = obs.expected_outcome in ("BLOCK", "DENY", "REQUIRE_APPROVAL")

            # System verdict: Actual decision
            is_detected = obs.actual_outcome in ("BLOCK", "DENY", "REQUIRE_APPROVAL")

            if obs.actual_outcome in ("BLOCK", "DENY"):
                blocks += 1
            elif obs.actual_outcome == "REQUIRE_APPROVAL":
                approvals += 1

            if is_adversarial and obs.complexity == "MULTI_STEP":
                multi_step_attack_count += 1
                if obs.interrupted_at_step is not None:
                    interrupted_count += 1

            if is_adversarial and is_detected:
                tp += 1
                f1_binary_samples.append(1.0)
            elif is_adversarial and not is_detected:
                fn += 1
                f1_binary_samples.append(0.0)
            elif not is_adversarial and is_detected:
                fp += 1
                f1_binary_samples.append(0.0)
            else:  # not is_adversarial and not is_detected
                tn += 1
                f1_binary_samples.append(1.0)

        precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
        recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
        f1 = round((2 * precision * recall) / (precision + recall), 4) if (precision + recall) > 0 else 0.0
        accuracy = round((tp + tn) / total, 4) if total > 0 else 0.0

        fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
        fnr = round(fn / (fn + tp), 4) if (fn + tp) > 0 else 0.0
        detection_rate = recall
        block_rate = round(blocks / total, 4) if total > 0 else 0.0
        approval_rate = round(approvals / total, 4) if total > 0 else 0.0

        chain_interruption_rate = (
            round(interrupted_count / multi_step_attack_count, 4)
            if multi_step_attack_count > 0
            else 0.0
        )

        # Latency statistics
        latencies_sorted = sorted(latencies)
        mean_lat = round(statistics.fmean(latencies_sorted), 2)
        med_lat = round(statistics.median(latencies_sorted), 2)
        min_lat = round(latencies_sorted[0], 2)
        max_lat = round(latencies_sorted[-1], 2)
        std_lat = round(statistics.stdev(latencies_sorted), 2) if len(latencies_sorted) > 1 else 0.0

        p95_idx = int(0.95 * (len(latencies_sorted) - 1))
        p99_idx = int(0.99 * (len(latencies_sorted) - 1))
        p95_lat = round(latencies_sorted[p95_idx], 2)
        p99_lat = round(latencies_sorted[p99_idx], 2)

        overhead = max(0.0, round(med_lat - baseline_latency_ms, 2))

        # Bootstrap 95% Confidence Intervals
        ci_f1_low, ci_f1_high = StatisticalAnalyzer.bootstrap_ci(f1_binary_samples, seed=seed)
        ci_lat_low, ci_lat_high = StatisticalAnalyzer.bootstrap_ci(latencies, seed=seed)

        return MetricResult(
            total_observations=total,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=precision,
            recall=recall,
            f1_score=f1,
            accuracy=accuracy,
            false_positive_rate=fpr,
            false_negative_rate=fnr,
            detection_rate=detection_rate,
            block_rate=block_rate,
            approval_rate=approval_rate,
            chain_interruption_rate=chain_interruption_rate,
            latency_mean_ms=mean_lat,
            latency_median_ms=med_lat,
            latency_p95_ms=p95_lat,
            latency_p99_ms=p99_lat,
            latency_std_ms=std_lat,
            latency_min_ms=min_lat,
            latency_max_ms=max_lat,
            security_overhead_ms=overhead,
            ci_f1_lower=ci_f1_low,
            ci_f1_upper=ci_f1_high,
            ci_latency_lower=ci_lat_low,
            ci_latency_upper=ci_lat_high,
        )

    @classmethod
    def compute_category_metrics(
        cls, observations: List[ScenarioObservation], seed: int = 42
    ) -> Dict[str, MetricResult]:
        """Compute separate MetricResult objects for each attack taxonomy category."""
        grouped: Dict[str, List[ScenarioObservation]] = {}
        for obs in observations:
            cat = obs.category
            if cat not in grouped:
                grouped[cat] = []
            grouped[cat].append(obs)

        return {
            cat: cls.compute_metrics(obs_list, seed=seed)
            for cat, obs_list in sorted(grouped.items())
        }

    @classmethod
    def compute_complexity_metrics(
        cls, observations: List[ScenarioObservation], seed: int = 42
    ) -> Dict[str, MetricResult]:
        """Compute separate MetricResult objects across graduated complexity levels."""
        grouped: Dict[str, List[ScenarioObservation]] = {}
        for obs in observations:
            cplx = obs.complexity
            if cplx not in grouped:
                grouped[cplx] = []
            grouped[cplx].append(obs)

        return {
            cplx: cls.compute_metrics(obs_list, seed=seed)
            for cplx, obs_list in sorted(grouped.items())
        }

    @classmethod
    def compute_control_attribution(
        cls, observations: List[ScenarioObservation]
    ) -> Dict[str, int]:
        """Tally causal control attributions across all observations."""
        attribution_counts: Dict[str, int] = {
            ControlAttribution.POLICY.value: 0,
            ControlAttribution.BEHAVIOR.value: 0,
            ControlAttribution.MULTI_AGENT.value: 0,
            ControlAttribution.EXECUTION_GATEWAY.value: 0,
            ControlAttribution.APPROVAL.value: 0,
            ControlAttribution.MULTIPLE_CONTROLS.value: 0,
            ControlAttribution.MISSED.value: 0,
        }

        for obs in observations:
            val = obs.attribution.value if hasattr(obs.attribution, "value") else str(obs.attribution)
            if val in attribution_counts:
                attribution_counts[val] += 1
            else:
                attribution_counts[val] = 1

        return attribution_counts
