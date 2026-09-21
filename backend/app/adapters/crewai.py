"""
AgentSentinel Phase 0.9: CrewAI Ecosystem Adapter (SUPPORTED).
Provides step callbacks and tool execution wrappers for CrewAI role-playing agents.
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


class CrewAIAdapter(AgentSentinelAdapter):
    """CrewAI framework adapter."""

    @property
    def framework_name(self) -> str:
        return "CrewAI"

    @property
    def status(self) -> AdapterStatus:
        return AdapterStatus.SUPPORTED


default_crewai_adapter = CrewAIAdapter()


class AgentSentinelCrewAIInterceptor:
    """
    Integrates with CrewAI step callbacks and custom tools.
    Binds agent persona, role, and task goal into the canonical security context.
    """

    def __init__(
        self,
        agent_id: Optional[str] = None,
        agent_role: str = "crew_specialist",
        session_id: str = "crewai_session",
        namespace: str = "default",
        client: Optional[Any] = None,
        adapter: Optional[CrewAIAdapter] = None,
        fail_closed: bool = True,
    ):
        self.agent_id = agent_id or f"crew_{agent_role}"
        self.agent_role = agent_role if agent_id is None else (agent_id or agent_role)
        self.session_id = session_id
        self.namespace = namespace
        self.client = client
        self.adapter = adapter or default_crewai_adapter
        self.fail_closed = fail_closed

    def step_callback(self, step_output: Any) -> Any:
        """
        Step callback invoked by CrewAI after each task step.
        Returns the step output intact.
        """
        logger.debug(f"CrewAIAdapter: Step completed in session '{self.session_id}' for role '{self.agent_role}'")
        return step_output

    def wrap_tool(
        self,
        tool_or_name: Any,
        tool_callable: Optional[Any] = None,
        task_summary: str = "",
    ) -> Any:
        """
        Wraps a tool callable or function to validate security policies prior to invocation.
        Accepts (tool_name, tool_callable) or (tool_callable, tool_name=...).
        """
        if tool_callable is not None:
            name = str(tool_or_name)
            tool = tool_callable
        else:
            tool = tool_or_name
            name = getattr(tool, "name", str(tool))

        def execute_guarded(*args: Any, **kwargs: Any) -> Any:
            arguments = dict(kwargs)
            if args:
                arguments["_args"] = list(args)

            try:
                if self.client is not None:
                    res = self.client.intercept(
                        tool_name=name,
                        agent_id=self.agent_id,
                        session_id=self.session_id,
                        namespace=self.namespace,
                        arguments=arguments,
                    )
                    decision = res.get("decision", "ALLOW") if isinstance(res, dict) else getattr(res, "decision", "ALLOW")
                    if decision != "ALLOW":
                        reason = res.get("reason", "CrewAI tool disallowed by policy") if isinstance(res, dict) else getattr(res, "reason", "CrewAI tool disallowed by policy")
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
                else:
                    req = CanonicalSecurityRequest(
                        agent_id=self.agent_id,
                        role=self.agent_role,
                        session_id=self.session_id,
                        tool_name=name,
                        arguments=arguments,
                        task_summary=task_summary,
                        framework_name=self.adapter.framework_name,
                        namespace=self.namespace,
                    )
                    self.adapter.enforce(req)
            except SecurityBlockedException:
                raise
            except Exception as e:
                logger.error(f"CrewAIAdapter: Unexpected error intercepting '{name}': {e}", exc_info=True)
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
                return None

            if callable(tool):
                return tool(*args, **kwargs)
            elif hasattr(tool, "run"):
                return tool.run(*args, **kwargs)
            elif hasattr(tool, "_run"):
                return tool._run(*args, **kwargs)
            raise ValueError(f"CrewAI tool '{name}' is not callable.")

        return execute_guarded

    def wrap_crew_tool(
        self,
        tool: Any,
        tool_name: Optional[str] = None,
        task_summary: str = "",
    ) -> Any:
        return self.wrap_tool(tool_or_name=tool_name or tool, tool_callable=tool if tool_name else None, task_summary=task_summary)
