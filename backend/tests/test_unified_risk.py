from app.anomaly.engine import UnifiedRiskEngine
from app.anomaly.thresholds import AnomalyLevel
from app.events.factory import apply_decision, create_security_event
from app.events.schema import PolicyResult
from app.interceptor.proxy import intercept_tool_call
from app.interceptor.schema import ToolCallRequest

def test_unified_risk_engine_benign_event():
    engine = UnifiedRiskEngine()
    event = create_security_event("s_u1", "a1", "u1", "google_search", {"query": "test"}, role="research_assistant")
    risk = engine.evaluate_risk(event, [])

    assert 0.0 <= risk.overall_score <= 1.0
    assert risk.severity == AnomalyLevel.LOW
    assert risk.recommended_action == "ALLOW"
    assert risk.confidence > 0.0
    assert len(risk.detector_results) == 5

def test_unified_risk_engine_critical_threat_escalation():
    engine = UnifiedRiskEngine()
    # History with multi-step probing
    h1 = create_security_event("s_u2", "a1", "u1", "google_search", {})
    h2 = create_security_event("s_u2", "a1", "u1", "read_system_file", {"filepath": "/etc/shadow"})
    h2.record_decision(PolicyResult.DENY, "Denied")

    # Current event: exfiltrating to disk
    curr = create_security_event("s_u2", "a1", "u1", "write_workspace_file", {"filepath": "keys.txt"}, role="research_assistant")

    risk = engine.evaluate_risk(curr, [h1, h2])

    assert risk.overall_score >= 0.85
    assert risk.severity == AnomalyLevel.CRITICAL
    assert risk.primary_detector in ["SequenceAnomalyDetector", "ToolTransitionDetector", "RoleCapabilityMismatchDetector"]
    assert len(risk.top_risk_factors) > 0
    assert len(risk.evidence) > 0

def test_unified_risk_engine_fail_closed_on_error():
    engine = UnifiedRiskEngine()
    broken_event = object()  # Not a valid SecurityEvent
    risk = engine.evaluate_risk(broken_event, [])

    assert risk.overall_score >= 0.85
    assert risk.severity == AnomalyLevel.CRITICAL
    assert risk.recommended_action == "BLOCK"
    assert "FailClosedGuard" in risk.primary_detector

def test_policy_precedence_preserves_policy_block(db_session):
    # Static policy blocks credential reads
    req = ToolCallRequest(
        session_id="sess_prec_1",
        agent_id="agent_1",
        user_id="user_1",
        tool_name="read_system_file",
        arguments={"filepath": "/home/user/.ssh/id_rsa"},
        role="code_assistant",
        target_resource="/home/user/.ssh/id_rsa",
    )
    resp = intercept_tool_call(req, db_session)
    # Policy was BLOCK; final decision MUST remain BLOCK
    assert resp.decision == "BLOCK"
    assert resp.execution_allowed is False

def test_behavioral_escalation_blocks_benign_policy_on_critical_sequence(db_session):
    # Execute rapid probing sequence in same session
    sess_id = "sess_prec_escalate"

    req1 = ToolCallRequest(session_id=sess_id, agent_id="a", user_id="u", tool_name="google_search", arguments={"q": "probe"}, role="research_assistant")
    intercept_tool_call(req1, db_session)

    req2 = ToolCallRequest(session_id=sess_id, agent_id="a", user_id="u", tool_name="read_system_file", arguments={"filepath": "/etc/shadow"}, role="research_assistant", target_resource="/etc/shadow")
    intercept_tool_call(req2, db_session)

    # 3rd request: write workspace file (policy might allow code assistant write, but research assistant sequence triggers critical behavioral block)
    req3 = ToolCallRequest(session_id=sess_id, agent_id="a", user_id="u", tool_name="write_workspace_file", arguments={"filepath": "out.txt"}, role="research_assistant")
    resp3 = intercept_tool_call(req3, db_session)

    assert resp3.decision == "BLOCK"
    assert resp3.execution_allowed is False
    assert "BEHAVIORAL BLOCK" in resp3.decision_reason
