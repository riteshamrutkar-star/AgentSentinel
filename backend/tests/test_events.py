import json
from app.events.factory import apply_decision, create_security_event, enrich_event_security
from app.events.model import SecurityEvent
from app.events.schema import ActionType, ApprovalStatus, ExecutionStage, PolicyResult, SensitivityLevel

def test_security_event_creation():
    event = create_security_event(
        session_id="sess_test_123",
        agent_id="agent_alpha",
        user_id="user_bob",
        tool_name="google_search",
        arguments_payload={"query": "security benchmarks"},
        role="research_assistant",
        framework_name="LangChain",
        target_resource="https://google.com",
        action_type=ActionType.NETWORK,
        task_summary="Find security benchmarks",
    )

    assert event.identity.session_id == "sess_test_123"
    assert event.identity.agent_id == "agent_alpha"
    assert event.tool_action.tool_name == "google_search"
    assert event.tool_action.action_type == ActionType.NETWORK
    assert event.tool_action.arguments_payload == {"query": "security benchmarks"}
    assert event.identity.event_id.startswith("evt_")
    assert event.execution_context.execution_allowed is True

def test_security_event_enrichment():
    event = create_security_event(
        session_id="sess_test_123",
        agent_id="agent_alpha",
        user_id="user_bob",
        tool_name="read_workspace_file",
        arguments_payload={"filepath": "config.json"},
    )

    enrich_event_security(
        event,
        sensitivity_level=SensitivityLevel.MEDIUM,
        policy_tags=["workspace_read"],
        risk_indicators=["ACCESS_WORKSPACE"],
        anomaly_score=0.15,
        threat_flags=["SAFE_WORKSPACE"],
    )

    assert event.security_context.sensitivity_level == SensitivityLevel.MEDIUM
    assert "workspace_read" in event.security_context.policy_tags
    assert "ACCESS_WORKSPACE" in event.security_context.risk_indicators
    assert event.security_context.anomaly_score == 0.15
    assert "SAFE_WORKSPACE" in event.security_context.threat_flags

def test_security_event_decision_lifecycle():
    event = create_security_event(
        session_id="sess_test_123",
        agent_id="agent_alpha",
        user_id="user_bob",
        tool_name="drop_database_table",
        arguments_payload={"table_name": "users"},
    )

    # Apply require approval
    apply_decision(
        event,
        policy_result=PolicyResult.REQUIRE_APPROVAL,
        reason="Destructive database drop requires approval",
        approval_required=True,
        approval_status=ApprovalStatus.PENDING,
    )

    assert event.decision_context.policy_result == PolicyResult.REQUIRE_APPROVAL
    assert event.decision_context.approval_required is True
    assert event.execution_context.execution_allowed is False

    # Record execution (if permitted later)
    event.record_execution(
        result_payload={"status": "dropped"},
        latency_ms=12.5,
    )
    assert event.execution_context.latency_ms == 12.5
    assert event.tool_action.execution_stage == ExecutionStage.POST_EXECUTION

def test_security_event_serialization():
    event = create_security_event(
        session_id="sess_test_123",
        agent_id="agent_alpha",
        user_id="user_bob",
        tool_name="google_search",
        arguments_payload={"query": "test"},
    )
    apply_decision(event, policy_result=PolicyResult.ALLOW, reason="Allowed by policy")

    event_dict = event.to_dict()
    assert isinstance(event_dict, dict)
    assert event_dict["identity"]["session_id"] == "sess_test_123"
    assert event_dict["decision_context"]["decision_result"] == "ALLOW"

    event_json = event.to_json()
    assert isinstance(event_json, str)
    parsed = json.loads(event_json)
    assert parsed["identity"]["event_id"] == event.identity.event_id
