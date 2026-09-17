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


# --- Phase 0.9 Event Streaming, Webhooks & SIEM Tests ---

import time
from app.events.publisher import EventPublisher, default_event_publisher
from app.events.webhooks import WebhookDeliveryManager, default_webhook_manager
from app.events.siem import GenericHTTPSIEMConnector, DatadogSIEMConnector
from unittest.mock import MagicMock


def test_event_publisher_v1_envelope_schema():
    publisher = EventPublisher()
    mock_event = create_security_event(
        session_id="sess_envelope",
        agent_id="agent_stream",
        user_id="user_stream",
        tool_name="web_search",
        arguments_payload={"query": "test"},
        namespace="finance-corp",
    )
    apply_decision(mock_event, policy_result=PolicyResult.ALLOW, reason="OK")

    envelope = publisher.build_envelope(mock_event)
    assert envelope["version"] == "1.0.0"
    assert envelope["source"] == "agentsentinel-control-plane"
    assert envelope["event_type"] == "SECURITY_EVENT"
    assert envelope["namespace"] == "finance-corp"
    assert envelope["event_id"] == mock_event.identity.event_id
    assert envelope["data"]["identity"]["session_id"] == "sess_envelope"


def test_webhook_hmac_signing_and_verification():
    secret = "test_signing_secret_key_12345"
    mgr = WebhookDeliveryManager(secret=secret)

    payload = {"event_id": "evt_test", "decision": "ALLOW", "timestamp": "2026-09-17T00:00:00Z"}
    ts = time.time()

    sig = mgr.sign_payload(payload, timestamp=ts)
    assert isinstance(sig, str)
    assert len(sig) == 64  # SHA-256 hex digest

    # Verify signature passes
    valid = mgr.verify_signature(payload, timestamp=ts, signature=sig)
    assert valid is True

    # Tampered signature fails
    assert mgr.verify_signature(payload, timestamp=ts, signature="bad" + sig[3:]) is False

    # Tampered timestamp fails
    assert mgr.verify_signature(payload, timestamp=ts + 1, signature=sig) is False

    # Tampered payload fails
    tampered = dict(payload)
    tampered["decision"] = "BLOCK"
    assert mgr.verify_signature(tampered, timestamp=ts, signature=sig) is False


def test_siem_connector_cef_format():
    connector = GenericHTTPSIEMConnector(endpoint="https://siem.internal/api/events", format="CEF")
    mock_event = create_security_event(
        session_id="sess_cef",
        agent_id="agent_cef",
        user_id="user_1",
        tool_name="bash_exec",
        arguments_payload={"cmd": "whoami"},
        namespace="prod-sec",
    )
    apply_decision(mock_event, policy_result=PolicyResult.DENY, reason="Command execution blocked")

    cef_string = connector.format_cef(mock_event)
    assert cef_string.startswith("CEF:0|AgentSentinel|ControlPlane|0.9.0|")
    assert "bash_exec" in cef_string
    assert "DENY" in cef_string
    assert "Command execution blocked" in cef_string


def test_siem_connector_datadog_payload():
    connector = DatadogSIEMConnector(api_key="dd_test_key", service="agentsentinel")
    mock_event = create_security_event(
        session_id="sess_dd",
        agent_id="agent_dd",
        user_id="user_2",
        tool_name="read_file",
        arguments_payload={"path": "/etc/passwd"},
        namespace="staging",
    )
    apply_decision(mock_event, policy_result=PolicyResult.DENY, reason="Sensitive file access prohibited")

    dd_payload = connector.build_datadog_event(mock_event)
    assert dd_payload["title"].startswith("AgentSentinel Security Event:")
    assert "agent_dd" in dd_payload["tags"]
    assert "namespace:staging" in dd_payload["tags"]
    assert "alert_type" in dd_payload
    assert dd_payload["alert_type"] == "error"

