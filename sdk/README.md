# AgentSentinel Python Developer SDK (`agentsentinel`)

The official Python Developer SDK for **AgentSentinel**, the unified AI-agent security control plane.

## Overview

The `agentsentinel` client library enables AI agent applications and orchestration workflows to interface seamlessly with the centralized AgentSentinel Control Plane.

### Key Features
- **Zero Local Policy Engine**: Contains no local security logic; all evaluation, behavioral risk analysis, and audit trails are executed authoritatively by the Control Plane.
- **Fail-Closed Security**: Configurable `fail_closed=True` mode ensures unmediated tool executions are strictly denied if communication fails.
- **Synchronous & Asynchronous Parity**: First-class `AgentSentinelClient` and `AsyncAgentSentinelClient`.
- **Durable Namespace Propagation**: Automatically tags and scopes all requests to tenant and environment boundaries.
- **Automatic Retries & Exponential Backoff**: Built-in jittered exponential backoff for transient network issues.

---

## Installation

```bash
pip install agentsentinel
```

---

## Quickstart

### Synchronous Client

```python
from agentsentinel import AgentSentinelClient, ActionType

client = AgentSentinelClient(
    base_url="http://localhost:8000",
    api_key="as_live_operator_key",
    namespace="production",
    fail_closed=True,
)

decision = client.intercept(
    session_id="sess_prod_01",
    agent_id="research_agent_v1",
    tool_name="database_query",
    action_type=ActionType.DATA_ACCESS,
    arguments={"query": "SELECT * FROM public.records"},
    raise_on_block=False,
)

if decision.allowed:
    print(f"Tool execution authorized! Event ID: {decision.event_id}")
else:
    print(f"Tool execution blocked: {decision.reason}")
```

### Asynchronous Client

```python
import asyncio
from agentsentinel import AsyncAgentSentinelClient, ActionType

async def main():
    client = AsyncAgentSentinelClient(
        base_url="http://localhost:8000",
        api_key="as_live_operator_key",
        namespace="production",
        fail_closed=True,
    )

    decision = await client.intercept(
        session_id="sess_async_01",
        agent_id="copilot_v2",
        tool_name="web_search",
        action_type=ActionType.NETWORK,
        arguments={"query": "security best practices"},
        raise_on_block=True,
    )
    print("Decision:", decision.decision)

asyncio.run(main())
```

---

## Error Handling

```python
from agentsentinel import (
    AgentSentinelClient,
    SecurityBlockedError,
    ApprovalPendingError,
    RateLimitExceededError,
    AuthenticationError,
)

client = AgentSentinelClient(base_url="http://localhost:8000", api_key="test_key")

try:
    decision = client.intercept(
        session_id="sess_err_1",
        agent_id="agent_1",
        tool_name="bash_exec",
        arguments={"cmd": "rm -rf /"},
        raise_on_block=True,
    )
except SecurityBlockedError as e:
    print(f"Action blocked by AgentSentinel: {e.reason} (Event: {e.event_id})")
except ApprovalPendingError as e:
    print(f"Action paused awaiting human approval: Event {e.event_id}")
except RateLimitExceededError as e:
    print(f"Rate limit exceeded. Retry after {e.retry_after}s")
```
