"""
AgentSentinel Phase 0.9: Microsoft Semantic Kernel Ecosystem Adapter (SUPPORTED).
Provides function invocation filters and plugin wrappers for Semantic Kernel Python.
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


class SemanticKernelAdapter(AgentSentinelAdapter):
    """Semantic Kernel framework adapter."""

    @property
    def framework_name(self) -> str:
        return "SemanticKernel"

    @property
    def status(self) -> AdapterStatus:
        return AdapterStatus.SUPPORTED


default_semantic_kernel_adapter = SemanticKernelAdapter()


class AgentSentinelKernelFilter:
    """
    Implements the Semantic Kernel Function Invocation Filter pattern.
    Intercepts kernel plugin function executions before invocation.
    """

    def __init__(
        self,
        agent_id: str = "semantic_kernel_agent",
        session_id: str = "sk_session",
        namespace: str = "default",
        client: Optional[Any] = None,
        adapter: Optional[SemanticKernelAdapter] = None,
        fail_closed: bool = True,
    ):
        self.agent_id = agent_id
        self.session_id = session_id
        self.namespace = namespace
        self.client = client
        self.adapter = adapter or default_semantic_kernel_adapter
        self.fail_closed = fail_closed

    def on_function_invoking(self, context: Any) -> bool:
        """
        Invoked before Semantic Kernel executes a plugin function.
        Raises SecurityBlockedException if AgentSentinel denies execution.
        """
        function = context.get("function") if isinstance(context, dict) else getattr(context, "function", None)
        plugin_name = ""
        function_name = ""
        if isinstance(function, dict):
            plugin_name = function.get("plugin_name", "")
            function_name = function.get("function_name") or function.get("name", "unknown")
        elif function is not None:
            plugin_name = getattr(function, "plugin_name", "")
            function_name = getattr(function, "name", getattr(function, "function_name", "unknown"))

        tool_name = f"{plugin_name}.{function_name}" if plugin_name else function_name

        arguments_obj = context.get("arguments", {}) if isinstance(context, dict) else getattr(context, "arguments", {})
        arguments = dict(arguments_obj) if hasattr(arguments_obj, "items") else {"args": str(arguments_obj)}

        try:
            if self.client is not None:
                res = self.client.intercept(
                    tool_name=tool_name,
                    agent_id=self.agent_id,
                    session_id=self.session_id,
                    namespace=self.namespace,
                    arguments=arguments,
                )
                decision = res.get("decision", "ALLOW") if isinstance(res, dict) else getattr(res, "decision", "ALLOW")
                if decision != "ALLOW":
                    reason = res.get("reason", "Semantic Kernel capability denied") if isinstance(res, dict) else getattr(res, "reason", "Semantic Kernel capability denied")
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
                return True

            req = CanonicalSecurityRequest(
                agent_id=self.agent_id,
                session_id=self.session_id,
                tool_name=tool_name,
                arguments=arguments,
                framework_name=self.adapter.framework_name,
                namespace=self.namespace,
            )
            self.adapter.enforce(req)
            return True
        except SecurityBlockedException:
            raise
        except Exception as e:
            logger.error(f"SemanticKernelAdapter: Unexpected error intercepting '{tool_name}': {e}", exc_info=True)
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
            return True

    def on_function_invoked(self, context: Any) -> None:
        """Audits successful completion of a Semantic Kernel function."""
        logger.debug(f"SemanticKernelAdapter: Function invoked cleanly in session '{self.session_id}'")

    def on_function_invocation(
        self,
        context: Any,
        next_filter: Optional[Callable[[Any], Any]] = None,
    ) -> Any:
        """
        Function invocation filter method.
        Extracts plugin name, function name, and arguments from context.
        Raises SecurityBlockedException if AgentSentinel denies execution.
        """
        # Duck-type extract function details from Semantic Kernel FunctionInvocationContext
        function = getattr(context, "function", None)
        plugin_name = getattr(function, "plugin_name", "default_plugin") if function else "default_plugin"
        function_name = getattr(function, "name", "unknown_function") if function else str(context)
        tool_name = f"{plugin_name}.{function_name}" if plugin_name else function_name

        arguments_obj = getattr(context, "arguments", {})
        arguments = dict(arguments_obj) if hasattr(arguments_obj, "items") else {"args": str(arguments_obj)}

        req = CanonicalSecurityRequest(
            agent_id=self.agent_id,
            session_id=self.session_id,
            tool_name=tool_name,
            arguments=arguments,
            framework_name=self.adapter.framework_name,
            namespace=self.namespace,
        )

        logger.debug(f"SemanticKernelAdapter: Intercepting function '{tool_name}' in session '{self.session_id}'")
        self.adapter.enforce(req)

        if next_filter is not None:
            return next_filter(context)
        return None

    def wrap_kernel_function(self, func: Callable[..., Any], plugin_name: str, function_name: str) -> Callable[..., Any]:
        """
        Wraps an individual Semantic Kernel plugin function with runtime security enforcement.
        """
        tool_name = f"{plugin_name}.{function_name}"

        def guarded_func(*args: Any, **kwargs: Any) -> Any:
            arguments = dict(kwargs)
            if args:
                arguments["_args"] = list(args)

            req = CanonicalSecurityRequest(
                agent_id=self.agent_id,
                session_id=self.session_id,
                tool_name=tool_name,
                arguments=arguments,
                framework_name=self.adapter.framework_name,
                namespace=self.namespace,
            )
            self.adapter.enforce(req)
            return func(*args, **kwargs)

        return guarded_func
