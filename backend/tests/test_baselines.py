from app.anomaly.baselines import SessionBaselineEngine
from app.events.factory import create_security_event

def test_baseline_cold_start():
    engine = SessionBaselineEngine()
    # Fewer than 3 events: cold start
    evt1 = create_security_event("s1", "a1", "u1", "google_search", {})
    baseline = engine.build_baseline("s1", "a1", "research_assistant", [evt1])

    assert baseline.is_established is False
    assert baseline.total_events == 1

    deviation = engine.calculate_deviation(evt1, baseline)
    assert deviation["baseline_established"] == 0.0
    assert deviation["composite_deviation"] == 0.0

def test_baseline_established_and_deviation():
    engine = SessionBaselineEngine()
    # 3 historical benign search events
    events = [
        create_security_event("s2", "a2", "u2", "google_search", {}),
        create_security_event("s2", "a2", "u2", "google_search", {}),
        create_security_event("s2", "a2", "u2", "google_search", {}),
    ]
    baseline = engine.build_baseline("s2", "a2", "research_assistant", events)

    assert baseline.is_established is True
    assert baseline.total_events == 3
    assert "google_search" in baseline.common_tools

    # Evaluate an event using a completely new, sensitive tool
    sensitive_event = create_security_event("s2", "a2", "u2", "read_system_file", {"filepath": "/etc/shadow"}, target_resource="/etc/shadow")
    deviation = engine.calculate_deviation(sensitive_event, baseline)

    assert deviation["baseline_established"] == 1.0
    assert deviation["unusual_tool_deviation"] == 1.0
    assert deviation["sensitivity_deviation"] == 1.0
    assert deviation["composite_deviation"] == 1.0
