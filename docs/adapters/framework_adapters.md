# AgentSentinel v1.0 — Canonical Ecosystem Framework Adapters

## 1. Supported Framework Integrations

AgentSentinel provides pre-built canonical adapters for the leading AI agent frameworks:

| Framework | Interceptor Class | Status | Hooks Intercepted | Fail-Closed Policy |
| :--- | :--- | :---: | :--- | :---: |
| **LangChain** | `AgentSentinelCallbackHandler`<br>`AgentSentinelToolWrapper` | `SUPPORTED` | `on_tool_start`, `on_tool_end`, `on_tool_error`, `run` | Enabled |
| **LangGraph** | `AgentSentinelNodeInterceptor` | `SUPPORTED` | `intercept_node_execution`, `intercept_node_tool_call` | Enabled |
| **AutoGen** | `AgentSentinelAutoGenInterceptor` | `SUPPORTED` | `intercept_agent_message`, `intercept_tool_execution` | Enabled |
| **CrewAI** | `AgentSentinelCrewAIInterceptor` | `SUPPORTED` | `step_callback`, `task_callback`, `wrap_tool` | Enabled |
| **Semantic Kernel** | `AgentSentinelKernelFilter` | `SUPPORTED` | `on_function_invoking`, `on_function_invoked` | Enabled |

---

## 2. Classification Definitions

- **SUPPORTED**: Functional adapter implementation and unit test coverage exist, but full real-runtime end-to-end framework certification is not demonstrated.
- **CERTIFIED**: Requires executing a real framework runtime in an end-to-end integration harness.
- **EXPERIMENTAL**: Implementation exists but compatibility is provisional.

---

## 3. Usage Examples

### LangChain Integration
```python
from langchain.agents import initialize_agent, AgentType
from app.adapters.langchain import AgentSentinelCallbackHandler
from sdk.agentsentinel import AgentSentinelClient

client = AgentSentinelClient(base_url="http://localhost:8000", api_key="live_key")
handler = AgentSentinelCallbackHandler(
    client=client,
    agent_id="langchain_agent_01",
    session_id="session_100",
    namespace="production",
    fail_closed=True,
)

# Pass handler into LangChain execution
# agent.run("Perform task", callbacks=[handler])
```

### LangGraph Node Interception
```python
from app.adapters.langgraph import AgentSentinelNodeInterceptor

interceptor = AgentSentinelNodeInterceptor(
    client=client,
    agent_id="graph_agent",
    session_id="session_200",
    namespace="production",
    fail_closed=True,
)

# Intercept tool invocation inside a graph node
result = interceptor.intercept_node_tool_call(
    node_name="research_node",
    tool_name="database_lookup",
    tool_fn=db_lookup_callable,
    tool_args={"id": 42},
)
```
