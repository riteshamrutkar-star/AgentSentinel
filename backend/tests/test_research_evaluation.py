"""
Unit tests for Research Metrics Evaluation Calculator (Phase 0.3).
"""

import pytest
from app.evaluation.research_metrics import (
    EvaluationCase,
    ResearchMetricsCalculator,
    ResearchMetricsSummary,
)


def test_empty_cases_metrics():
    summary = ResearchMetricsCalculator.calculate_metrics([])
    assert summary.total_evaluations == 0
    assert summary.precision == 0.0
    assert summary.recall == 0.0
    assert summary.f1_score == 0.0


def test_perfect_classification():
    cases = [
        EvaluationCase(
            scenario_id="case_1",
            scenario_name="Safe Read",
            ground_truth_is_anomalous=False,
            policy_verdict="ALLOW",
            behavioral_anomaly_score=0.10,
            behavioral_triggered=False,
            final_decision="ALLOW",
            execution_allowed=True,
            latency_ms=2.5,
        ),
        EvaluationCase(
            scenario_id="case_2",
            scenario_name="Exfiltration Attack",
            ground_truth_is_anomalous=True,
            policy_verdict="ALLOW",
            behavioral_anomaly_score=0.92,
            behavioral_triggered=True,
            final_decision="BLOCK",
            execution_allowed=False,
            latency_ms=4.1,
        ),
    ]

    summary = ResearchMetricsCalculator.calculate_metrics(cases)
    assert summary.total_evaluations == 2
    assert summary.true_positives == 1
    assert summary.true_negatives == 1
    assert summary.false_positives == 0
    assert summary.false_negatives == 0
    assert summary.precision == 1.0
    assert summary.recall == 1.0
    assert summary.f1_score == 1.0
    assert summary.false_positive_rate == 0.0
    assert summary.false_negative_rate == 0.0
    assert summary.min_latency_ms == 2.5
    assert summary.max_latency_ms == 4.1
    assert summary.avg_latency_ms == 3.3


def test_mixed_confusion_matrix_calculations():
    cases = [
        # TP: anomalous ground truth, detected anomalous
        EvaluationCase(
            scenario_id="c_tp",
            scenario_name="TP",
            ground_truth_is_anomalous=True,
            policy_verdict="DENY",
            behavioral_anomaly_score=0.85,
            behavioral_triggered=True,
            final_decision="BLOCK",
            execution_allowed=False,
            latency_ms=3.0,
        ),
        # FP: benign ground truth, falsely flagged anomalous
        EvaluationCase(
            scenario_id="c_fp",
            scenario_name="FP",
            ground_truth_is_anomalous=False,
            policy_verdict="ALLOW",
            behavioral_anomaly_score=0.72,
            behavioral_triggered=True,
            final_decision="REQUIRE_APPROVAL",
            execution_allowed=False,
            latency_ms=3.0,
        ),
        # TN: benign ground truth, correctly passed
        EvaluationCase(
            scenario_id="c_tn",
            scenario_name="TN",
            ground_truth_is_anomalous=False,
            policy_verdict="ALLOW",
            behavioral_anomaly_score=0.15,
            behavioral_triggered=False,
            final_decision="ALLOW",
            execution_allowed=True,
            latency_ms=3.0,
        ),
        # FN: anomalous ground truth, missed (falsely passed)
        EvaluationCase(
            scenario_id="c_fn",
            scenario_name="FN",
            ground_truth_is_anomalous=True,
            policy_verdict="ALLOW",
            behavioral_anomaly_score=0.20,
            behavioral_triggered=False,
            final_decision="ALLOW",
            execution_allowed=True,
            latency_ms=3.0,
        ),
    ]

    summary = ResearchMetricsCalculator.calculate_metrics(cases)
    assert summary.total_evaluations == 4
    assert summary.true_positives == 1
    assert summary.false_positives == 1
    assert summary.true_negatives == 1
    assert summary.false_negatives == 1

    # Precision = TP / (TP + FP) = 1 / 2 = 0.5
    assert summary.precision == 0.5
    # Recall = TP / (TP + FN) = 1 / 2 = 0.5
    assert summary.recall == 0.5
    # F1 = 2 * (0.5 * 0.5) / (0.5 + 0.5) = 0.5
    assert summary.f1_score == 0.5
    # FPR = FP / (FP + TN) = 1 / 2 = 0.5
    assert summary.false_positive_rate == 0.5
    # FNR = FN / (FN + TP) = 1 / 2 = 0.5
    assert summary.false_negative_rate == 0.5
    # Layer breakdowns
    assert summary.policy_blocks_count == 1
    assert summary.behavioral_detections_count == 2
    assert summary.final_blocked_count == 1
    assert summary.final_allowed_count == 2
    assert summary.final_approval_required_count == 1
