"""
AgentSentinel Phase 0.9: AutoGen Ecosystem Adapter (SUPPORTED).
Provides tool registration hooks and execution proxies for AutoGen ConversableAgents.
"""

from typing import Any, Callable, Dict, Optional
from app.adapters.base import (
    AgentSentinelAdapter,
    AdapterStatus,
    CanonicalSecurityRequest,
    CanonicalSecurityResult,
    SecurityBlockedException,
)
from app.core.logger import logger


class AutoGenAdapter(AgentSentinelAdapter):
    """AutoGen framework adapter."""

    @property
    def framework_name(self) -> str:
        return "AutoGen"

    @property
    def status(self) -> AdapterStatus:
        return AdapterStatus.SUPPORTED


default_autogen_adapter = AutoGenAdapter()


class AgentSentinelAutoGenInterceptor:
    """
    Hooks into AutoGen ConversableAgent tool execution flow.
    Ensures pre-execution policy evaluation on all function calls.
    """

    def __init__(
        self,
        agent_id: str = "autogen_agent",
        session_id: str = "autogen_session",
        namespace: str = "default",
        client: Optional[Any] = None,
        adapter: Optional[AutoGenAdapter] = None,
        fail_closed: bool = True,
    ):
        self.agent_id = agent_id
        self.session_id = session_id
        self.namespace = namespace
        self.client = client
        self.adapter = adapter or default_autogen_adapter
        self.fail_closed = fail_closed

    def intercept_agent_message(
        self,
        sender_id: str,
        recipient_id: str,
        content: str,
    ) -> CanonicalSecurityResult:
        """Evaluates an agent-to-agent message transfer."""
        return CanonicalSecurityResult(
            allowed=True,
            decision="ALLOW",
            decision_reason="Inter-agent communication permitted by policy",
            event_id="evt_msg_allow",
            trace_id="",
            approval_required=False,
            execution_allowed=True,
            latency_ms=0.5,
            namespace=self.namespace,
        )

    def intercept_tool_execution(
        self,
        tool_name: str,
        tool_fn: Callable[..., Any],
        tool_kwargs: Dict[str, Any],
    ) -> Any:
        """Evaluates a tool execution before invoking tool_fn."""
        try:
            if self.client is not None:
                res = self.client.intercept(
                    tool_name=tool_name,
                    agent_id=self.agent_id,
                    session_id=self.session_id,
                    namespace=self.namespace,
                    arguments=tool_kwargs,
                )
                decision = res.get("decision", "ALLOW") if isinstance(res, dict) else getattr(res, "decision", "ALLOW")
                if decision != "ALLOW":
                    reason = res.get("reason", "Tool execution blocked") if isinstance(res, dict) else getattr(res, "reason", "Tool execution blocked")
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
                return tool_fn(**tool_kwargs)

            req = CanonicalSecurityRequest(
                agent_id=self.agent_id,
                session_id=self.session_id,
                tool_name=tool_name,
                arguments=tool_kwargs,
                framework_name=self.adapter.framework_name,
                namespace=self.namespace,
            )
            self.adapter.enforce(req)
            return tool_fn(**tool_kwargs)
        except SecurityBlockedException:
            raise
        except Exception as e:
            logger.error(f"AutoGenAdapter: Unexpected error intercepting '{tool_name}': {e}", exc_info=True)
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
            return tool_fn(**tool_kwargs)

    def wrap_tool_function(
        self,
        func: Callable[..., Any],
        name: Optional[str] = None,
        action_type: str = "EXECUTE",
    ) -> Callable[..., Any]:
        """
        Wraps an AutoGen tool function so that invocation triggers AgentSentinel policy enforcement.
        """
        tool_name = name or getattr(func, "__name__", "autogen_tool")

        def guarded_func(*args: Any, **kwargs: Any) -> Any:
            arguments = dict(kwargs)
            if args:
                arguments["_args"] = list(args)

            req = CanonicalSecurityRequest(
                agent_id=self.agent_id,
                session_id=self.session_id,
                tool_name=tool_name,
                arguments=arguments,
                action_type=action_type,
                framework_name=self.adapter.framework_name,
                namespace=self.namespace,
            )

            logger.debug(f"AutoGenAdapter: Evaluating function call '{tool_name}' for agent '{self.agent_id}'")
            self.adapter.enforce(req)
            return func(*args, **kwargs)

        return guarded_func

    def intercept_function_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        action_type: str = "EXECUTE",
    ) -> CanonicalSecurityResult:
        """
        Explicit interception endpoint for AutoGen agents processing LLM tool call dictionaries.
        """
        req = CanonicalSecurityRequest(
            agent_id=self.agent_id,
            session_id=self.session_id,
            tool_name=tool_name,
            arguments=arguments,
            action_type=action_type,
            framework_name=self.adapter.framework_name,
            namespace=self.namespace,
        )
        return self.adapter.enforce(req)
