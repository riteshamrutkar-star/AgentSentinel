from unittest.mock import MagicMock, patch
from app.agent.runner import LangChainAgentRunner
from app.agent.tools import SecuredTool, get_secured_tool_registry

def test_secured_tool_executes_only_when_allowed(db_session):
    mock_func = MagicMock(return_value="executed_successfully")
    tool = SecuredTool(
        name="test_tool",
        func=mock_func,
        description="Test tool",
        action_type="NETWORK",
    )

    result = tool.invoke(
        tool_input={"query": "hello"},
        session_id="sess_agent_allow",
        agent_id="agent_1",
        user_id="user_1",
        role="research_assistant",
        task_summary="Search test",
        db=db_session,
    )

    assert result["verdict"] == "ALLOW"
    assert result["execution_allowed"] is True
    assert result["status"] == "SUCCESS"
    assert result["output"] == "executed_successfully"
    mock_func.assert_called_once_with(query="hello")

def test_secured_tool_never_executes_when_blocked(db_session):
    mock_func = MagicMock(return_value="should_not_run")
    tool = SecuredTool(
        name="read_system_file",
        func=mock_func,
        description="System file tool",
        action_type="READ",
    )

    result = tool.invoke(
        tool_input={"filepath": "/home/user/.ssh/id_rsa"},
        session_id="sess_agent_block",
        agent_id="agent_2",
        user_id="user_2",
        role="code_assistant",
        task_summary="Steal SSH keys",
        db=db_session,
    )

    assert result["verdict"] == "BLOCK"
    assert result["execution_allowed"] is False
    assert result["status"] == "BLOCKED"
    assert "prohibited by AgentSentinel" in result["output"]
    # Guarantee function was never called!
    mock_func.assert_not_called()

def test_secured_tool_pauses_for_approval_without_executing(db_session):
    mock_func = MagicMock(return_value="dropped")
    tool = SecuredTool(
        name="drop_database_table",
        func=mock_func,
        description="Drop DB tool",
        action_type="DATABASE",
    )

    result = tool.invoke(
        tool_input={"table_name": "orders"},
        session_id="sess_agent_appr",
        agent_id="agent_3",
        user_id="user_3",
        role="database_admin",
        task_summary="Drop table",
        db=db_session,
    )

    assert result["verdict"] == "REQUIRE_APPROVAL"
    assert result["execution_allowed"] is False
    assert result["status"] == "PAUSED_FOR_APPROVAL"
    assert "requires human administrator sign-off" in result["output"]
    # Guarantee function was never called!
    mock_func.assert_not_called()

def test_secured_tool_fails_closed_on_interception_error(db_session):
    mock_func = MagicMock(return_value="executed_despite_error")
    tool = SecuredTool(
        name="test_tool",
        func=mock_func,
        description="Test tool",
        action_type="READ",
    )

    with patch("app.agent.tools.intercept_tool_call", side_effect=RuntimeError("Interception pipeline crash")):
        result = tool.invoke(
            tool_input={"filepath": "test.txt"},
            session_id="sess_agent_err",
            agent_id="agent_err",
            user_id="user_err",
            role="research_assistant",
            task_summary="Error test",
            db=db_session,
        )

        assert result["verdict"] == "BLOCK"
        assert result["execution_allowed"] is False
        assert result["status"] == "BLOCKED"
        mock_func.assert_not_called()

def test_langchain_agent_runner_unknown_tool(db_session):
    runner = LangChainAgentRunner(session_id="sess_runner_1")
    result = runner.execute_tool_action(
        tool_name="nonexistent_tool_xyz",
        tool_input={},
        task_summary="Unknown tool test",
        db=db_session,
    )
    assert result["status"] == "ERROR"
    assert result["verdict"] == "UNKNOWN_TOOL"
    assert result["execution_allowed"] is False
