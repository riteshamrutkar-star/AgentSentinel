"""
Framework Adapter Foundation for AgentSentinel Phase 0.4.
Provides an extensible adapter protocol for integrating multi-agent frameworks
(LangChain, CrewAI, AutoGen, custom swarms) with AgentSentinel multi-agent governance.
"""

import uuid
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.core.logger import logger
from app.interceptor.schema import ToolCallRequest
from app.multiagent.delegation import default_delegation_manager
from app.multiagent.interceptor import default_message_interceptor
from app.multiagent.models import (
    AgentCapability,
    AgentMessage,
    DelegationDecision,
    MessageType,
    utc_now,
)
from app.multiagent.registry import default_agent_registry


class AgentFrameworkAdapter(ABC):
    """Abstract protocol for multi-agent framework adapters."""

    @abstractmethod
    def delegate_action(
        self,
        sender_agent_id: str,
        recipient_agent_id: str,
        session_id: str,
        action_name: str,
        capabilities: List[AgentCapability],
        provenance: Optional[List[str]] = None,
        db: Optional[Session] = None,
    ) -> DelegationDecision:
        """Mediates and executes an agent-to-agent delegation request."""
        pass

    @abstractmethod
    def execute_delegated_tool(
        self,
        delegation_id: str,
        executing_agent_id: str,
        tool_name: str,
        tool_input: Dict[str, Any],
        session_id: str,
        db: Session,
    ) -> Dict[str, Any]:
        """Executes a tool under an authorized delegation token."""
        pass


class LangChainMultiAgentAdapter(AgentFrameworkAdapter):
    """
    Concrete Multi-Agent Governance Adapter for LangChain-based multi-agent teams.
    Governs coordinator-to-worker delegations, enforces capability boundaries,
    and attaches full provenance to delegated tool execution events.
    """

    def __init__(self):
        self.message_interceptor = default_message_interceptor
        self.delegation_manager = default_delegation_manager
        self.agent_registry = default_agent_registry

    def get_tool_registry(self):
        from app.agent.tools import get_secured_tool_registry
        return get_secured_tool_registry()

    def delegate_action(
        self,
        sender_agent_id: str,
        recipient_agent_id: str,
        session_id: str,
        action_name: str,
        capabilities: List[AgentCapability],
        provenance: Optional[List[str]] = None,
        db: Optional[Session] = None,
    ) -> DelegationDecision:
        """
        Submits an agent-to-agent delegation request through the AgentMessageInterceptor.
        Returns the structured security decision (ALLOW, BLOCK, REQUIRE_APPROVAL).
        """
        import uuid

        msg = AgentMessage(
            message_id=f"msg_{uuid.uuid4().hex[:8]}",
            sender_agent_id=sender_agent_id,
            recipient_agent_id=recipient_agent_id,
            session_id=session_id,
            timestamp=utc_now(),
            message_type=MessageType.DELEGATION_REQUEST,
            requested_action=action_name,
            requested_capabilities=capabilities,
            payload_metadata={"framework": "LangChain", "adapter": "LangChainMultiAgentAdapter"},
            provenance=provenance or [sender_agent_id],
        )

        return self.message_interceptor.intercept_message(message=msg, db=db)

    def execute_delegated_tool(
        self,
        delegation_id: str,
        executing_agent_id: str,
        tool_name: str,
        tool_input: Dict[str, Any],
        session_id: str,
        db: Session,
    ) -> Dict[str, Any]:
        """
        Executes a tool call on behalf of a delegated agent, enforcing that:
        1. The delegation token exists, is active, and unexpired.
        2. The executing agent matches the authorized delegatee.
        3. The tool's capability is within the granted delegation scope.
        """
        from app.agent.tools import SecuredTool
        from app.interceptor.proxy import intercept_tool_call

        tool_registry = self.get_tool_registry()

        # 1. Validate tool exists
        if tool_name not in tool_registry:
            return {
                "status": "ERROR",
                "verdict": "UNKNOWN_TOOL",
                "execution_allowed": False,
                "output": f"Tool '{tool_name}' is not registered in SecuredTool registry.",
                "interceptor_response": None,
            }

        secured_tool: SecuredTool = tool_registry[tool_name]
        agent = self.agent_registry.get_agent(executing_agent_id, db)
        role = agent.role if agent else "default_agent"

        # Determine target resource
        resource = str(tool_input.get("filepath", tool_input.get("table_name", tool_input.get("query", ""))))

        # 2. Build ToolCallRequest with delegation attributes
        req = ToolCallRequest(
            session_id=session_id,
            agent_id=executing_agent_id,
            user_id=f"delegated_{executing_agent_id}",
            tool_name=tool_name,
            arguments=tool_input,
            role=role,
            framework_name="LangChain-MultiAgent",
            target_resource=resource,
            action_type=secured_tool.action_type,
            task_summary=f"Delegated tool execution via token {delegation_id}",
            delegation_id=delegation_id,
        )

        # 3. Mediate through proxy
        interceptor_response = intercept_tool_call(req, db)

        # 4. Enforce execution outcome through SecureExecutionGateway
        if interceptor_response.decision == "ALLOW" and interceptor_response.execution_allowed:
            from app.execution.models import ExecutionContext, ExecutionState
            from app.execution.gateway import default_execution_gateway
            exec_ctx = ExecutionContext(
                execution_id=f"exec_{uuid.uuid4().hex[:10]}",
                agent_id=executing_agent_id,
                delegation_id=delegation_id,
                session_id=session_id,
                tool_id=tool_name,
                tool_name=tool_name,
                arguments=tool_input,
                capabilities=agent.capabilities if agent else [],
                resource_scope=resource,
                policy_decision=interceptor_response.decision,
                approval_id=interceptor_response.event_id,
                approval_event_id=interceptor_response.event_id,
                timeout_seconds=10.0,
            )

            exec_res = default_execution_gateway.execute(exec_ctx, handler=secured_tool.func, db=db)

            if exec_res.status == ExecutionState.COMPLETED:
                return {
                    "status": "SUCCESS",
                    "verdict": "ALLOW",
                    "execution_allowed": True,
                    "output": exec_res.sanitized_output,
                    "interceptor_response": interceptor_response.model_dump(),
                    "execution_id": exec_res.execution_id,
                    "execution_time_ms": exec_res.execution_time_ms,
                    "execution_backend": exec_res.execution_backend.value,
                }
            else:
                return {
                    "status": "BLOCKED",
                    "verdict": "BLOCK",
                    "execution_allowed": False,
                    "output": f"SECURITY VERDICT: BLOCK. Action '{tool_name}' failed execution sandbox check. Reason: {exec_res.error_message or exec_res.sanitized_output}",
                    "interceptor_response": interceptor_response.model_dump(),
                    "execution_id": exec_res.execution_id,
                }
        else:
            return {
                "status": "BLOCKED" if interceptor_response.decision == "BLOCK" else "PAUSED_FOR_APPROVAL",
                "verdict": interceptor_response.decision,
                "execution_allowed": False,
                "output": f"SECURITY VERDICT: {interceptor_response.decision}. Reason: {interceptor_response.decision_reason}",
                "interceptor_response": interceptor_response.model_dump(),
            }


default_multiagent_adapter = LangChainMultiAgentAdapter()
