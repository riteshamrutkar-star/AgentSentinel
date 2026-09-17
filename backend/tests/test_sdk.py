"""
Unit and integration tests for AgentSentinel Phase 0.9: Developer Python SDK.
Verifies sync and async clients, exception mappings, idempotency header propagation,
and guarantees ZERO local policy evaluation logic in the SDK.
"""

import pytest
from unittest.mock import MagicMock, patch

from agentsentinel import (
    AgentSentinelClient,
    AsyncAgentSentinelClient,
    SecurityBlockedError,
    ApprovalPendingError,
    RateLimitExceededError,
    ConflictError,
    AuthenticationError,
    AgentSentinelError,
)


# --- 1. Zero Local Policy Engine Verification ---

def test_sdk_has_zero_local_policy_engine():
    """Verify that SDK does not import or evaluate local policy rules."""
    import sdk.agentsentinel.client as client_mod

    # Confirm policy module is not imported in SDK client
    assert not hasattr(client_mod, "PolicyEngine")
    assert not hasattr(client_mod, "evaluate_policy")
    assert not hasattr(client_mod, "default_policy_engine")


# --- 2. Synchronous Client Tests ---

@patch("agentsentinel.client.httpx.Client")
def test_sync_client_intercept_allow(mock_httpx_cls):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "event_id": "evt_sdk_001",
        "decision": "ALLOW",
        "execution_allowed": True,
        "reason": "Policy permits search action",
        "latency_ms": 1.2,
    }
    mock_instance = MagicMock()
    mock_instance.post.return_value = mock_response
    mock_httpx_cls.return_value = mock_instance

    client = AgentSentinelClient(
        base_url="https://sentinel.local",
        api_key="test-api-key",
        namespace="testing",
    )

    res = client.intercept(
        tool_name="google_search",
        arguments={"query": "test"},
        agent_id="sdk_agent",
        session_id="sess_sdk_1",
    )
    assert res["decision"] == "ALLOW"
    assert res["execution_allowed"] is True

    # Check request headers
    mock_instance.post.assert_called_once()
    headers = mock_instance.post.call_args[1]["headers"]
    assert headers["Authorization"] == "Bearer test-api-key"
    assert headers["X-Namespace"] == "testing"


@patch("agentsentinel.client.httpx.Client")
def test_sync_client_intercept_blocked(mock_httpx_cls):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "event_id": "evt_sdk_block",
        "decision": "BLOCK",
        "execution_allowed": False,
        "reason": "Dangerous filesystem access denied",
        "latency_ms": 2.0,
    }
    mock_instance = MagicMock()
    mock_instance.post.return_value = mock_response
    mock_httpx_cls.return_value = mock_instance

    client = AgentSentinelClient(base_url="https://sentinel.local", api_key="k")

    with pytest.raises(SecurityBlockedError) as exc_info:
        client.intercept(
            tool_name="delete_files",
            arguments={"path": "/"},
            agent_id="sdk_agent",
            session_id="sess_1",
            raise_on_block=True,
        )
    assert "Dangerous filesystem access denied" in str(exc_info.value)
    assert exc_info.value.event_id == "evt_sdk_block"


@patch("agentsentinel.client.httpx.Client")
def test_sync_client_rate_limit_error(mock_httpx_cls):
    mock_response = MagicMock()
    mock_response.status_code = 429
    mock_response.headers = {"Retry-After": "15"}
    mock_response.json.return_value = {"detail": "Rate limit exceeded"}
    mock_instance = MagicMock()
    mock_instance.post.return_value = mock_response
    mock_httpx_cls.return_value = mock_instance

    client = AgentSentinelClient(base_url="https://sentinel.local", api_key="k")

    with pytest.raises(RateLimitExceededError) as exc_info:
        client.intercept(
            tool_name="search",
            arguments={},
            agent_id="a",
            session_id="s",
        )
    assert exc_info.value.retry_after == 15
    assert exc_info.value.status_code == 429


@patch("agentsentinel.client.httpx.Client")
def test_sync_client_idempotency_header(mock_httpx_cls):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"execution_id": "exec_1", "status": "COMPLETED"}
    mock_instance = MagicMock()
    mock_instance.post.return_value = mock_response
    mock_httpx_cls.return_value = mock_instance

    client = AgentSentinelClient(base_url="https://sentinel.local", api_key="k")
    client.submit_execution(
        session_id="sess_1",
        agent_id="agent_1",
        tool_name="calc",
        idempotency_key="idem_uuid_12345",
    )

    headers = mock_instance.post.call_args[1]["headers"]
    assert headers["Idempotency-Key"] == "idem_uuid_12345"


# --- 3. Asynchronous Client Tests ---

@pytest.mark.asyncio
async def test_async_client_intercept():
    with patch("agentsentinel.client.httpx.AsyncClient") as mock_async_cls:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "event_id": "evt_async_001",
            "decision": "ALLOW",
            "execution_allowed": True,
            "reason": "Async allowed",
        }
        mock_instance = MagicMock()
        # Mocking async post
        async def async_post(*args, **kwargs):
            return mock_response

        mock_instance.post = async_post
        mock_async_cls.return_value = mock_instance

        async with AsyncAgentSentinelClient(base_url="https://sentinel.local", api_key="k") as client:
            res = await client.intercept(
                tool_name="query_docs",
                arguments={"id": 1},
                agent_id="async_agent",
                session_id="sess_async",
            )
            assert res["decision"] == "ALLOW"
            assert res["execution_allowed"] is True
