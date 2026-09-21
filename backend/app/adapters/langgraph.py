"""
AgentSentinel Phase 0.9: LangGraph Ecosystem Adapter (SUPPORTED).
Provides graph node interception and state validation for cyclical, multi-agent LangGraph workflows.
"""

from typing import Any, Callable, Dict, List, Optional
from app.adapters.base import (
    AgentSentinelAdapter,
    AdapterStatus,
    CanonicalSecurityRequest,
    CanonicalSecurityResult,
    SecurityBlockedException,
)
from app.core.logger import logger


class LangGraphAdapter(AgentSentinelAdapter):
    """LangGraph framework adapter."""

    @property
    def framework_name(self) -> str:
        return "LangGraph"

    @property
    def status(self) -> AdapterStatus:
        return AdapterStatus.SUPPORTED


default_langgraph_adapter = LangGraphAdapter()


class AgentSentinelNodeInterceptor:
    """
    Wraps LangGraph execution nodes.
    Pre-flight validates any tool calls present in the graph state before node execution.
    """

    def __init__(
        self,
        agent_id: str = "langgraph_agent",
        session_id: str = "langgraph_session",
        namespace: str = "default",
        client: Optional[Any] = None,
        adapter: Optional[LangGraphAdapter] = None,
        fail_closed: bool = True,
    ):
        self.agent_id = agent_id
        self.session_id = session_id
        self.namespace = namespace
        self.client = client
        self.adapter = adapter or default_langgraph_adapter
        self.fail_closed = fail_closed

    def intercept_node_tool_call(
        self,
        node_name: str,
        tool_name: str,
        tool_fn: Callable[..., Any],
        tool_args: Dict[str, Any],
    ) -> Any:
        """
        Explicitly evaluates a node tool call before invoking tool_fn.
        Raises SecurityBlockedException if blocked.
        """
        try:
            if self.client is not None:
                res = self.client.intercept(
                    tool_name=tool_name,
                    agent_id=self.agent_id,
                    session_id=self.session_id,
                    namespace=self.namespace,
                    arguments=tool_args,
                )
                decision = res.get("decision", "ALLOW") if isinstance(res, dict) else getattr(res, "decision", "ALLOW")
                if decision != "ALLOW":
                    reason = res.get("reason", "Node tool execution blocked") if isinstance(res, dict) else getattr(res, "reason", "Node tool execution blocked")
                    event_id = res.get("event_id") if isinstance(res, dict) else getattr(res, "event_id", None)
                    canonical_res = CanonicalSecurityResult(
                        allowed=False,
                        decision=decision,
                        decision_reason=reason,
                        event_id=event_id or "",
                        trace_id="",
                        approval_required=False,
                        execution_allowed=False,
                        latency_ms=0.0,
                        namespace=self.namespace,
                    )
                    raise SecurityBlockedException(reason, result=canonical_res)
                return tool_fn(**tool_args)

            req = CanonicalSecurityRequest(
                agent_id=self.agent_id,
                session_id=self.session_id,
                tool_name=tool_name,
                arguments=tool_args,
                framework_name=self.adapter.framework_name,
                namespace=self.namespace,
            )
            self.adapter.enforce(req)
            return tool_fn(**tool_args)
        except SecurityBlockedException:
            raise
        except Exception as e:
            logger.error(f"LangGraphAdapter: Unexpected error intercepting node tool '{tool_name}': {e}", exc_info=True)
            if self.fail_closed:
                sanitized_reason = "Tool execution blocked: Security evaluation failed closed due to an internal error."
                canonical_res = CanonicalSecurityResult(
                    allowed=False,
                    decision="BLOCK",
                    decision_reason=sanitized_reason,
                    event_id="evt_internal_error",
                    trace_id="",
                    approval_required=False,
                    execution_allowed=False,
                    latency_ms=0.0,
                    namespace=self.namespace,
                )
                raise SecurityBlockedException(sanitized_reason, result=canonical_res)
            return tool_fn(**tool_args)

    def intercept_state_tool_calls(self, state: Dict[str, Any]) -> List[CanonicalSecurityResult]:
        """
        Inspects state messages for tool calls and evaluates each through AgentSentinel.
        Raises SecurityBlockedException if any tool call violates security policies.
        """
        results: List[CanonicalSecurityResult] = []
        messages = state.get("messages", [])

        for msg in messages:
            tool_calls = getattr(msg, "tool_calls", None) or (msg.get("tool_calls") if isinstance(msg, dict) else None)
            if not tool_calls:
                continue

            for tc in tool_calls:
                name = tc.get("name") if isinstance(tc, dict) else getattr(tc, "name", "unknown")
                args = tc.get("args") if isinstance(tc, dict) else getattr(tc, "args", {})

                req = CanonicalSecurityRequest(
                    agent_id=self.agent_id,
                    session_id=self.session_id,
                    tool_name=name,
                    arguments=args if isinstance(args, dict) else {"raw_args": args},
                    framework_name=self.adapter.framework_name,
                    namespace=self.namespace,
                )

                logger.debug(f"LangGraphAdapter: Intercepting tool call '{name}' in graph state")
                res = self.adapter.enforce(req)
                results.append(res)

        return results

    def wrap_node(self, node_fn: Callable[[Dict[str, Any]], Dict[str, Any]]) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
        """
        Decorator wrapping a LangGraph node function with security interception.
        """
        def guarded_node(state: Dict[str, Any], *args: Any, **kwargs: Any) -> Dict[str, Any]:
            self.intercept_state_tool_calls(state)
            return node_fn(state, *args, **kwargs)

        return guarded_node
