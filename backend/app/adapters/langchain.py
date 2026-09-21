"""
AgentSentinel Phase 0.9: LangChain Ecosystem Adapter (SUPPORTED).
Provides both an asynchronous/synchronous CallbackHandler and a ToolWrapper
to intercept, audit, and enforce security policies on LangChain tool executions.
"""

from typing import Any, Dict, Optional, Union
from app.adapters.base import (
    AgentSentinelAdapter,
    AdapterStatus,
    CanonicalSecurityRequest,
    CanonicalSecurityResult,
    SecurityBlockedException,
)
from app.core.logger import logger

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.tools import BaseTool
    HAS_LANGCHAIN = True
except ImportError:
    HAS_LANGCHAIN = False
    # Graceful fallback base classes for duck-typing
    class BaseCallbackHandler:
        pass
    class BaseTool:
        pass


class LangChainAdapter(AgentSentinelAdapter):
    """LangChain framework adapter implementation."""

    @property
    def framework_name(self) -> str:
        return "LangChain"

    @property
    def status(self) -> AdapterStatus:
        return AdapterStatus.SUPPORTED


default_langchain_adapter = LangChainAdapter()


class AgentSentinelCallbackHandler(BaseCallbackHandler):
    """
    LangChain callback handler intercepting tool execution events.
    Enforces runtime security policies before tools run and audits execution outcomes.
    """

    def __init__(
        self,
        agent_id: str = "langchain_agent",
        session_id: str = "langchain_session",
        user_id: str = "default_user",
        namespace: str = "default",
        client: Optional[Any] = None,
        adapter: Optional[LangChainAdapter] = None,
        fail_closed: bool = True,
    ):
        self.agent_id = agent_id
        self.session_id = session_id
        self.user_id = user_id
        self.namespace = namespace
        self.client = client
        self.adapter = adapter or default_langchain_adapter
        self.fail_closed = fail_closed

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: Union[str, Dict[str, Any]],
        **kwargs: Any,
    ) -> None:
        """
        Intercepts tool call initiation.
        Normalizes input and invokes AgentSentinel security evaluation.
        Raises SecurityBlockedException on policy violation.
        """
        tool_name = serialized.get("name") or kwargs.get("name", "unknown_tool")
        args_payload = input_str if isinstance(input_str, dict) else {"input": input_str}

        try:
            if self.client is not None:
                res = self.client.intercept(
                    tool_name=tool_name,
                    agent_id=self.agent_id,
                    session_id=self.session_id,
                    namespace=self.namespace,
                    arguments=args_payload,
                    user_id=self.user_id,
                )
                decision = res.get("decision", "ALLOW") if isinstance(res, dict) else getattr(res, "decision", "ALLOW")
                if decision != "ALLOW":
                    reason = res.get("reason", "Blocked by policy") if isinstance(res, dict) else getattr(res, "reason", "Blocked by policy")
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
                return

            req = CanonicalSecurityRequest(
                agent_id=self.agent_id,
                session_id=self.session_id,
                tool_name=tool_name,
                arguments=args_payload,
                framework_name=self.adapter.framework_name,
                namespace=self.namespace,
                user_id=self.user_id,
            )

            logger.debug(f"LangChainAdapter: Intercepting tool start '{tool_name}' for agent '{self.agent_id}'")
            self.adapter.enforce(req)
        except SecurityBlockedException:
            raise
        except Exception as e:
            logger.error(
                f"LangChainAdapter: Unexpected internal error during interception for tool '{tool_name}' "
                f"in session '{self.session_id}': {e}",
                exc_info=True,
            )
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
            else:
                logger.warning(f"LangChainAdapter: Failing open (fail_closed=False) for tool '{tool_name}'.")
                return

    def on_tool_end(self, output: Any, **kwargs: Any) -> None:
        """Audits successful tool completion."""
        logger.debug(f"LangChainAdapter: Tool executed successfully in session '{self.session_id}'")

    def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
        """Audits tool errors."""
        logger.debug(f"LangChainAdapter: Tool error in session '{self.session_id}': {error}")


class AgentSentinelToolWrapper:
    """
    Wraps an existing tool callable or LangChain BaseTool, inserting
    pre-execution AgentSentinel policy evaluation.
    """

    def __init__(
        self,
        tool: Any = None,
        tool_instance: Any = None,
        tool_name: Optional[str] = None,
        client: Optional[Any] = None,
        agent_id: str = "langchain_agent",
        session_id: str = "langchain_session",
        namespace: str = "default",
        adapter: Optional[LangChainAdapter] = None,
    ):
        self.tool = tool if tool is not None else tool_instance
        self.name = tool_name or getattr(self.tool, "name", str(self.tool))
        self.client = client
        self.agent_id = agent_id
        self.session_id = session_id
        self.namespace = namespace
        self.adapter = adapter or default_langchain_adapter

    def _enforce(self, args_payload: Dict[str, Any]) -> None:
        if self.client is not None:
            res = self.client.intercept(
                tool_name=self.name,
                agent_id=self.agent_id,
                session_id=self.session_id,
                namespace=self.namespace,
                arguments=args_payload,
            )
            decision = res.get("decision", "ALLOW") if isinstance(res, dict) else getattr(res, "decision", "ALLOW")
            if decision != "ALLOW":
                reason = res.get("reason", "Blocked by policy") if isinstance(res, dict) else getattr(res, "reason", "Blocked by policy")
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
            return

        req = CanonicalSecurityRequest(
            agent_id=self.agent_id,
            session_id=self.session_id,
            tool_name=self.name,
            arguments=args_payload,
            framework_name=self.adapter.framework_name,
            namespace=self.namespace,
        )
        self.adapter.enforce(req)

    def run(self, *args: Any, **kwargs: Any) -> Any:
        args_payload = dict(kwargs)
        if args:
            args_payload["_positional_args"] = list(args)
        self._enforce(args_payload)

        if hasattr(self.tool, "run"):
            return self.tool.run(*args, **kwargs)
        elif hasattr(self.tool, "_run"):
            return self.tool._run(*args, **kwargs)
        elif callable(self.tool):
            return self.tool(*args, **kwargs)
        raise ValueError(f"Wrapped tool '{self.name}' is not runnable.")

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self.run(*args, **kwargs)
