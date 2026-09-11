"""
Research-Ready Evaluation Metrics for AgentSentinel Phase 0.3.
Calculates formal statistical and information-retrieval metrics:
Precision, Recall, F1, False Positive Rate, False Negative Rate, Detection Rate,
and Processing Latency Overhead, clearly distinguishing Policy Blocks from Behavioral Detections.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class EvaluationCase(BaseModel):
    """Execution telemetry and ground-truth label for a single benchmark scenario."""
    scenario_id: str
    scenario_name: str
    ground_truth_is_anomalous: bool
    policy_verdict: str                  # ALLOW, DENY, REQUIRE_APPROVAL
    behavioral_anomaly_score: float     # 0.0 to 1.0
    behavioral_triggered: bool          # score >= 0.65
    final_decision: str                 # ALLOW, BLOCK, REQUIRE_APPROVAL
    execution_allowed: bool
    latency_ms: float
    primary_detector: Optional[str] = None
    explanation: Optional[str] = None

class ResearchMetricsSummary(BaseModel):
    """Comprehensive statistical evaluation metrics summary."""
    total_evaluations: int = 0
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0

    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    false_positive_rate: float = 0.0
    false_negative_rate: float = 0.0
    detection_rate: float = 0.0

    # Explicit breakdown of enforcement layers
    policy_blocks_count: int = 0
    behavioral_detections_count: int = 0
    final_blocked_count: int = 0
    final_allowed_count: int = 0
    final_approval_required_count: int = 0

    avg_latency_ms: float = 0.0
    min_latency_ms: float = 0.0
    max_latency_ms: float = 0.0

class ResearchMetricsCalculator:
    """Calculates formal research-ready benchmark metrics from controlled scenario runs."""

    @staticmethod
    def calculate_metrics(cases: List[EvaluationCase]) -> ResearchMetricsSummary:
        total = len(cases)
        if total == 0:
            return ResearchMetricsSummary()

        tp = 0
        fp = 0
        tn = 0
        fn = 0

        policy_blocks = 0
        behavioral_detections = 0
        final_blocked = 0
        final_allowed = 0
        final_approval = 0
        latencies: List[float] = []

        for c in cases:
            latencies.append(c.latency_ms)

            if c.policy_verdict == "DENY":
                policy_blocks += 1

            if c.behavioral_triggered:
                behavioral_detections += 1

            if c.final_decision == "BLOCK":
                final_blocked += 1
            elif c.final_decision == "ALLOW":
                final_allowed += 1
            elif c.final_decision == "REQUIRE_APPROVAL":
                final_approval += 1

            # Confusion Matrix:
            # Positive = Ground truth was anomalous / malicious
            # Negative = Ground truth was benign
            predicted_anomalous = c.behavioral_triggered or (c.final_decision in ("BLOCK", "REQUIRE_APPROVAL"))

            if c.ground_truth_is_anomalous and predicted_anomalous:
                tp += 1
            elif (not c.ground_truth_is_anomalous) and predicted_anomalous:
                fp += 1
            elif (not c.ground_truth_is_anomalous) and (not predicted_anomalous):
                tn += 1
            elif c.ground_truth_is_anomalous and (not predicted_anomalous):
                fn += 1

        # Calculate ratios safely
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
        detection_rate = recall

        avg_lat = sum(latencies) / len(latencies) if latencies else 0.0

        return ResearchMetricsSummary(
            total_evaluations=total,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1, 4),
            false_positive_rate=round(fpr, 4),
            false_negative_rate=round(fnr, 4),
            detection_rate=round(detection_rate, 4),
            policy_blocks_count=policy_blocks,
            behavioral_detections_count=behavioral_detections,
            final_blocked_count=final_blocked,
            final_allowed_count=final_allowed,
            final_approval_required_count=final_approval,
            avg_latency_ms=round(avg_lat, 2),
            min_latency_ms=round(min(latencies), 2) if latencies else 0.0,
            max_latency_ms=round(max(latencies), 2) if latencies else 0.0,
        )
