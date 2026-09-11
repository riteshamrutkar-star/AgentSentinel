from app.events.factory import create_security_event
from app.events.schema import ActionType, PolicyResult
from app.policy.engine import PolicyEngine, default_policy_engine

def test_policy_allow_research_assistant():
    event = create_security_event(
        session_id="sess_1",
        agent_id="agent_1",
        user_id="user_1",
        tool_name="google_search",
        arguments_payload={"query": "agent safety"},
        role="research_assistant",
        action_type=ActionType.NETWORK,
    )
    result = default_policy_engine.evaluate(event)
    assert result.verdict == "ALLOW"
    assert result.execution_allowed is True
    assert result.approval_required is False
    assert event.decision_context.policy_result == PolicyResult.ALLOW

def test_policy_block_credential_access():
    event = create_security_event(
        session_id="sess_2",
        agent_id="agent_2",
        user_id="user_2",
        tool_name="read_system_file",
        arguments_payload={"filepath": "/home/user/.ssh/id_rsa"},
        role="code_assistant",
        target_resource="/home/user/.ssh/id_rsa",
        action_type=ActionType.READ,
    )
    result = default_policy_engine.evaluate(event)
    assert result.verdict == "BLOCK"
    assert result.execution_allowed is False
    assert result.approval_required is False
    assert event.decision_context.policy_result == PolicyResult.DENY
    assert "SEC_BLOCK_CREDENTIALS" in result.matched_rule_id

def test_policy_windows_path_normalization():
    # Test Windows absolute backslash path against unix glob pattern
    event = create_security_event(
        session_id="sess_win",
        agent_id="agent_win",
        user_id="user_win",
        tool_name="read_system_file",
        arguments_payload={"filepath": r"C:\Users\Administrator\.ssh\id_rsa"},
        role="code_assistant",
        target_resource=r"C:\Users\Administrator\.ssh\id_rsa",
        action_type=ActionType.READ,
    )
    result = default_policy_engine.evaluate(event)
    assert result.verdict == "BLOCK"
    assert result.execution_allowed is False
    assert "SEC_BLOCK_CREDENTIALS" in result.matched_rule_id

def test_policy_require_approval_destructive_db():
    event = create_security_event(
        session_id="sess_db",
        agent_id="agent_db",
        user_id="user_db",
        tool_name="drop_database_table",
        arguments_payload={"table_name": "audit_logs"},
        role="database_admin",
        target_resource="audit_logs",
        action_type=ActionType.DATABASE,
    )
    result = default_policy_engine.evaluate(event)
    assert result.verdict == "REQUIRE_APPROVAL"
    assert result.execution_allowed is False
    assert result.approval_required is True
    assert event.decision_context.policy_result == PolicyResult.REQUIRE_APPROVAL
    assert "ABAC_DESTRUCTIVE_DB_APPROVAL" in result.matched_rule_id

def test_policy_engine_fail_closed_on_corrupted_event():
    # Construct an engine and test with broken/corrupted object
    engine = PolicyEngine()
    broken_event = object()  # Not a SecurityEvent, missing required attributes
    result = engine.evaluate(broken_event)
    assert result.verdict == "BLOCK"
    assert result.execution_allowed is False
    assert "Fail Closed" in result.matched_rule_name
