from app.anomaly.features import BehavioralFeatureExtractor
from app.anomaly.scorer import StatisticalAnomalyScorer
from app.anomaly.thresholds import AnomalyLevel
from app.events.factory import create_security_event
from app.events.schema import PolicyResult

def test_feature_extractor_empty_session():
    features = BehavioralFeatureExtractor.extract_features(
        events=[],
        current_tool_name="google_search",
        current_role="research_assistant",
    )
    assert features["sequence_length"] == 1.0
    assert features["denied_count"] == 0.0
    assert features["sensitive_action_count"] == 0.0
    assert features["burst_count"] == 0.0

def test_feature_extractor_probing_sequence():
    evt1 = create_security_event("s1", "a1", "u1", "google_search", {"query": "test"})
    evt1.record_decision(PolicyResult.ALLOW, "Allowed")
    evt2 = create_security_event("s1", "a1", "u1", "read_system_file", {"filepath": "/etc/shadow"})
    evt2.record_decision(PolicyResult.DENY, "Denied")

    features = BehavioralFeatureExtractor.extract_features(
        events=[evt1, evt2],
        current_tool_name="write_workspace_file",
        current_role="research_assistant",
    )
    assert features["sequence_length"] == 3.0
    assert features["denied_count"] >= 1.0
    assert features["sensitive_action_count"] >= 1.0
    assert features["transition_penalty"] > 0.0
    assert features["role_mismatch"] > 0.0  # research_assistant using write_file

def test_anomaly_scorer_baseline_score():
    features = {
        "sequence_length": 1.0,
        "denied_count": 0.0,
        "sensitive_action_count": 0.0,
        "burst_count": 0.0,
        "ratio_denied": 0.0,
        "transition_penalty": 0.0,
        "role_mismatch": 0.0,
    }
    result = StatisticalAnomalyScorer.score_session_features("sess_clean", features)
    assert result.anomaly_score == 0.05
    assert result.anomaly_level == AnomalyLevel.LOW
    assert result.flagged is False
    assert result.recommended_action == "ALLOW"

def test_anomaly_scorer_score_clamping():
    # Provide extreme feature values to test score clamping at 1.0
    features = {
        "sequence_length": 10.0,
        "denied_count": 20.0,
        "sensitive_action_count": 20.0,
        "burst_count": 15.0,
        "ratio_denied": 1.0,
        "transition_penalty": 0.8,
        "role_mismatch": 0.8,
    }
    result = StatisticalAnomalyScorer.score_session_features("sess_extreme", features)
    assert result.anomaly_score == 1.0
    assert result.anomaly_level == AnomalyLevel.CRITICAL
    assert result.flagged is True
    assert result.recommended_action == "BLOCK"

def test_anomaly_scorer_none_and_nan_safety():
    # Ensure scorer handles empty dictionary or corrupted values safely
    result = StatisticalAnomalyScorer.score_session_features("sess_corrupt", None)
    assert 0.0 <= result.anomaly_score <= 1.0
    assert result.anomaly_level == AnomalyLevel.LOW
