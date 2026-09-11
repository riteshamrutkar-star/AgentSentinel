from app.anomaly.detectors import (
    BurstFrequencyDetector,
    RoleCapabilityMismatchDetector,
    SequenceAnomalyDetector,
    StatisticalBaselineDetector,
    ToolTransitionDetector,
)
from app.events.factory import create_security_event

def test_statistical_baseline_detector():
    detector = StatisticalBaselineDetector()
    assert detector.name == "StatisticalBaselineDetector"
    assert detector.weight > 0.0

    event = create_security_event("s1", "a1", "u1", "google_search", {})
    context = {"features": {"denied_count": 2.0, "sensitive_action_count": 1.0, "burst_events_count": 0.0}}
    res = detector.detect(event, [], context)

    assert 0.0 <= res.score <= 1.0
    assert res.score > 0.30  # elevated due to denied and sensitive actions
    assert len(res.evidence) >= 2

def test_sequence_anomaly_detector_probe_to_exfiltrate():
    detector = SequenceAnomalyDetector()
    event = create_security_event("s2", "a2", "u2", "write_workspace_file", {"filepath": "out.txt"})
    context = {
        "features": {
            "tool_sequence": ["google_search", "read_system_file", "write_workspace_file"],
            "current_is_sensitive": True,
            "denied_count": 1,
            "action_types": ["NETWORK", "READ", "WRITE"],
        }
    }
    res = detector.detect(event, [], context)

    assert res.score >= 0.85
    assert res.triggered is True
    assert res.metadata.get("matched_pattern") == "PROBE_TO_EXFILTRATE_SEQUENCE"
    assert "Attack chain detected" in res.evidence[0]

def test_sequence_anomaly_detector_recon_before_destruction():
    detector = SequenceAnomalyDetector()
    event = create_security_event("s3", "a3", "u3", "drop_database_table", {"table_name": "orders"})
    context = {
        "features": {
            "tool_sequence": ["google_search", "read_workspace_file", "drop_database_table"],
            "current_is_sensitive": True,
            "denied_count": 0,
        }
    }
    res = detector.detect(event, [], context)

    assert res.score >= 0.85
    assert res.triggered is True
    assert res.metadata.get("matched_pattern") == "RECON_BEFORE_DESTRUCTION"

def test_burst_frequency_detector_burst_spike():
    detector = BurstFrequencyDetector()
    event = create_security_event("s4", "a4", "u4", "google_search", {})
    context = {
        "features": {
            "burst_events_count": 4,
            "min_interval_seconds": 0.25,
            "calls_last_minute": 12,
            "repeat_tool_count": 4,
        }
    }
    res = detector.detect(event, [], context)

    assert res.score >= 0.65
    assert res.triggered is True
    assert any("Rapid burst detected" in ev for ev in res.evidence)
    assert any("Endpoint hammering" in ev for ev in res.evidence)

def test_tool_transition_detector_high_risk_transition():
    detector = ToolTransitionDetector()
    event = create_security_event("s5", "a5", "u5", "write_workspace_file", {})
    context = {
        "features": {
            "previous_tool": "read_system_file",
            "transition_pair": ("read_system_file", "write_workspace_file"),
            "action_types": ["READ", "WRITE"],
        }
    }
    res = detector.detect(event, [], context)

    assert res.score >= 0.85
    assert res.triggered is True
    assert "High-risk transition detected" in res.evidence[0]

def test_role_capability_mismatch_detector():
    detector = RoleCapabilityMismatchDetector()
    # research_assistant attempting destructive database drop
    event = create_security_event(
        "s6", "a6", "u6",
        tool_name="drop_database_table",
        arguments_payload={"table_name": "audit"},
        role="research_assistant",
    )
    context = {"features": {}}
    res = detector.detect(event, [], context)

    assert res.score >= 0.85
    assert res.triggered is True
    assert any("Explicit role violation" in ev or "Privilege overreach" in ev for ev in res.evidence)
