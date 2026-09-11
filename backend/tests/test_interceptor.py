from unittest.mock import patch
from app.interceptor.proxy import intercept_tool_call
from app.interceptor.schema import ToolCallRequest

def test_interceptor_allow_flow(db_session):
    request = ToolCallRequest(
        session_id="sess_int_allow",
        agent_id="agent_1",
        user_id="user_1",
        tool_name="google_search",
        arguments={"query": "pytest fast api"},
        role="research_assistant",
        action_type="NETWORK",
        target_resource="https://google.com",
    )
    response = intercept_tool_call(request, db_session)
    assert response.decision == "ALLOW"
    assert response.execution_allowed is True
    assert response.approval_required is False
    assert response.stored is True
    assert response.event_id.startswith("evt_")

def test_interceptor_block_flow(db_session):
    request = ToolCallRequest(
        session_id="sess_int_block",
        agent_id="agent_2",
        user_id="user_2",
        tool_name="read_system_file",
        arguments={"filepath": "/etc/shadow"},
        role="code_assistant",
        action_type="READ",
        target_resource="/etc/shadow",
    )
    response = intercept_tool_call(request, db_session)
    assert response.decision == "BLOCK"
    assert response.execution_allowed is False
    assert response.approval_required is False
    assert response.stored is True

def test_interceptor_require_approval_flow(db_session):
    request = ToolCallRequest(
        session_id="sess_int_appr",
        agent_id="agent_3",
        user_id="user_3",
        tool_name="drop_database_table",
        arguments={"table_name": "users"},
        role="database_admin",
        action_type="DATABASE",
        target_resource="users",
    )
    response = intercept_tool_call(request, db_session)
    assert response.decision == "REQUIRE_APPROVAL"
    assert response.execution_allowed is False
    assert response.approval_required is True
    assert response.stored is True

def test_interceptor_fail_closed_on_unexpected_error(db_session):
    request = ToolCallRequest(
        session_id="sess_int_err",
        agent_id="agent_err",
        user_id="user_err",
        tool_name="google_search",
        arguments={"query": "test"},
    )
    # Simulate an unexpected critical crash inside normalize_tool_call_request
    with patch("app.interceptor.proxy.normalize_tool_call_request", side_effect=RuntimeError("Simulated critical error")):
        response = intercept_tool_call(request, db_session)
        assert response.decision == "BLOCK"
        assert response.execution_allowed is False
        assert "fail-closed" in response.decision_reason
