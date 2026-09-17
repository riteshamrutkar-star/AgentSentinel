"""
Unit and integration tests for AgentSentinel Phase 0.9: Ecosystem Framework Adapters.
Tests canonical adapters for LangChain, LangGraph, AutoGen, CrewAI, and Semantic Kernel.
Verifies uniform canonical request translation, metadata enrichment, and SecurityBlockedException enforcement.
"""

import pytest
from unittest.mock import MagicMock

from app.adapters.base import (
    CanonicalSecurityRequest,
    CanonicalSecurityResult,
    SecurityBlockedException,
)
from app.adapters.langchain import AgentSentinelCallbackHandler, AgentSentinelToolWrapper
from app.adapters.langgraph import AgentSentinelNodeInterceptor
from app.adapters.autogen import AgentSentinelAutoGenInterceptor
from app.adapters.crewai import AgentSentinelCrewAIInterceptor
from app.adapters.semantic_kernel import AgentSentinelKernelFilter


# --- Mock Client Factory ---

def create_mock_client(verdict: str = "ALLOW", reason: str = "Authorized by policy"):
    client = MagicMock()
    if verdict == "ALLOW":
        client.intercept.return_value = {
            "decision": "ALLOW",
            "reason": reason,
            "event_id": "evt_allow_123",
            "execution_allowed": True,
            "latency_ms": 1.5,
        }
    else:
        client.intercept.return_value = {
            "decision": "BLOCK",
            "reason": reason,
            "event_id": "evt_block_456",
            "execution_allowed": False,
            "latency_ms": 2.1,
        }
    return client


# --- 1. LangChain Adapter Tests ---

def test_langchain_callback_handler_allow():
    client = create_mock_client("ALLOW")
    handler = AgentSentinelCallbackHandler(
        client=client,
        agent_id="langchain_agent_1",
        session_id="sess_lc_101",
        namespace="default",
    )

    # Tool start should mediate through client without throwing
    handler.on_tool_start(
        serialized={"name": "calculator"},
        input_str="2 + 2",
    )
    assert client.intercept.called
    call_args = client.intercept.call_args[1]
    assert call_args["tool_name"] == "calculator"
    assert call_args["agent_id"] == "langchain_agent_1"


def test_langchain_callback_handler_block():
    client = create_mock_client("BLOCK", reason="Malicious math injection")
    handler = AgentSentinelCallbackHandler(
        client=client,
        agent_id="langchain_agent_1",
        session_id="sess_lc_102",
        fail_closed=True,
    )

    with pytest.raises(SecurityBlockedException) as exc_info:
        handler.on_tool_start(
            serialized={"name": "system_exec"},
            input_str="rm -rf /",
        )
    assert "Malicious math injection" in str(exc_info.value)
    assert exc_info.value.event_id == "evt_block_456"


def test_langchain_tool_wrapper_execution():
    client = create_mock_client("ALLOW")
    mock_tool = MagicMock()
    mock_tool.name = "web_search"
    mock_tool.run.return_value = "Search results for query"

    wrapped = AgentSentinelToolWrapper(
        tool=mock_tool,
        client=client,
        agent_id="lc_wrapped_agent",
        session_id="sess_wrap_1",
    )

    result = wrapped.run(query="Python 3.13 features")
    assert result == "Search results for query"
    assert mock_tool.run.called


# --- 2. LangGraph Adapter Tests ---

def test_langgraph_node_interceptor_allow():
    client = create_mock_client("ALLOW")
    interceptor = AgentSentinelNodeInterceptor(
        client=client,
        agent_id="langgraph_agent",
        session_id="sess_lg_01",
    )

    target_tool = MagicMock(return_value={"retrieved": 42})
    result = interceptor.intercept_node_tool_call(
        node_name="research_node",
        tool_name="database_lookup",
        tool_fn=target_tool,
        tool_args={"id": 42},
    )
    assert result == {"retrieved": 42}
    assert target_tool.called


def test_langgraph_node_interceptor_block():
    client = create_mock_client("BLOCK", reason="Unauthorized node database access")
    interceptor = AgentSentinelNodeInterceptor(
        client=client,
        agent_id="langgraph_agent",
        session_id="sess_lg_02",
        fail_closed=True,
    )

    target_tool = MagicMock()
    with pytest.raises(SecurityBlockedException) as exc_info:
        interceptor.intercept_node_tool_call(
            node_name="untrusted_node",
            tool_name="delete_all_records",
            tool_fn=target_tool,
            tool_args={"table": "users"},
        )
    assert "Unauthorized node database access" in str(exc_info.value)
    assert not target_tool.called


# --- 3. AutoGen Adapter Tests ---

def test_autogen_interceptor_message_and_tool():
    client = create_mock_client("ALLOW")
    interceptor = AgentSentinelAutoGenInterceptor(
        client=client,
        agent_id="autogen_coordinator",
        session_id="sess_ag_01",
    )

    # Message interception
    msg_decision = interceptor.intercept_agent_message(
        sender_id="autogen_coordinator",
        recipient_id="autogen_worker",
        content="Please summarize document",
    )
    assert msg_decision.decision == "ALLOW"

    # Tool interception
    tool_fn = MagicMock(return_value="executed successfully")
    out = interceptor.intercept_tool_execution(
        tool_name="summarize",
        tool_fn=tool_fn,
        tool_kwargs={"doc_id": "doc_99"},
    )
    assert out == "executed successfully"


def test_autogen_interceptor_tool_block():
    client = create_mock_client("BLOCK", reason="AutoGen privilege violation")
    interceptor = AgentSentinelAutoGenInterceptor(
        client=client,
        agent_id="autogen_rogue",
        session_id="sess_ag_02",
        fail_closed=True,
    )

    tool_fn = MagicMock()
    with pytest.raises(SecurityBlockedException) as exc_info:
        interceptor.intercept_tool_execution(
            tool_name="bash_command",
            tool_fn=tool_fn,
            tool_kwargs={"cmd": "cat /etc/shadow"},
        )
    assert "AutoGen privilege violation" in str(exc_info.value)
    assert not tool_fn.called


# --- 4. CrewAI Adapter Tests ---

def test_crewai_interceptor_allow():
    client = create_mock_client("ALLOW")
    interceptor = AgentSentinelCrewAIInterceptor(
        client=client,
        agent_id="crewai_researcher",
        session_id="sess_crew_01",
    )

    step_output = {"tool": "wikipedia", "tool_input": "Agentic AI", "result": "AI info"}
    res = interceptor.step_callback(step_output)
    assert res == step_output

    mock_tool = MagicMock(return_value="Crew tool ran")
    wrapped_fn = interceptor.wrap_tool("scrape_website", mock_tool)
    assert wrapped_fn(url="https://news.ycombinator.com") == "Crew tool ran"


def test_crewai_interceptor_block():
    client = create_mock_client("BLOCK", reason="CrewAI tool disallowed by policy")
    interceptor = AgentSentinelCrewAIInterceptor(
        client=client,
        agent_id="crewai_agent_bad",
        session_id="sess_crew_02",
        fail_closed=True,
    )

    mock_tool = MagicMock()
    wrapped_fn = interceptor.wrap_tool("malicious_tool", mock_tool)

    with pytest.raises(SecurityBlockedException) as exc_info:
        wrapped_fn(payload="exploit")
    assert "CrewAI tool disallowed by policy" in str(exc_info.value)
    assert not mock_tool.called


# --- 5. Semantic Kernel Adapter Tests ---

def test_semantic_kernel_filter_allow():
    client = create_mock_client("ALLOW")
    sk_filter = AgentSentinelKernelFilter(
        client=client,
        agent_id="sk_copilot",
        session_id="sess_sk_01",
    )

    context = {
        "function": {"plugin_name": "WriterPlugin", "function_name": "FormatText"},
        "arguments": {"text": "raw markdown"},
    }
    allowed = sk_filter.on_function_invoking(context)
    assert allowed is True

    # Post invocation hook executes cleanly
    sk_filter.on_function_invoked({"result": "formatted"})


def test_semantic_kernel_filter_block():
    client = create_mock_client("BLOCK", reason="Semantic Kernel dangerous capability denied")
    sk_filter = AgentSentinelKernelFilter(
        client=client,
        agent_id="sk_copilot",
        session_id="sess_sk_02",
        fail_closed=True,
    )

    context = {
        "function": {"plugin_name": "SystemPlugin", "function_name": "ExecuteBinary"},
        "arguments": {"path": "/bin/sh"},
    }
    with pytest.raises(SecurityBlockedException) as exc_info:
        sk_filter.on_function_invoking(context)
    assert "Semantic Kernel dangerous capability denied" in str(exc_info.value)
