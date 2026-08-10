from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session
from app.agent.prompts import get_formatted_system_prompt
from app.agent.tools import SecuredTool, get_secured_tool_registry

class LangChainAgentRunner:
    """
    LangChain AI Agent Runner integrated with AgentSentinel Security Layer.
    Executes tasks and tool invocations while ensuring 100% of tool calls are mediated
    through AgentSentinel (Interceptor Proxy -> RBAC/ABAC Policy -> Anomaly Engine -> PostgreSQL Audit).
    """

    def __init__(
        self,
        session_id: str,
        agent_id: str = "agent_langchain_v1",
        user_id: str = "user_alice",
        role: str = "research_assistant",
        framework_name: str = "LangChain",
    ):
        self.session_id = session_id
        self.agent_id = agent_id
        self.user_id = user_id
        self.role = role
        self.framework_name = framework_name
        self.tool_registry = get_secured_tool_registry()

    def get_system_prompt(self) -> str:
        """Returns agent system prompt with active session credentials."""
        return get_formatted_system_prompt(
            agent_id=self.agent_id,
            user_id=self.user_id,
            role=self.role,
            session_id=self.session_id,
        )

    def execute_tool_action(
        self,
        tool_name: str,
        tool_input: Dict[str, Any],
        task_summary: str,
        db: Session
    ) -> Dict[str, Any]:
        """
        Executes a single mediated tool action through the SecuredTool registry.
        """
        if tool_name not in self.tool_registry:
            return {
                "status": "ERROR",
                "verdict": "UNKNOWN_TOOL",
                "execution_allowed": False,
                "output": f"Tool '{tool_name}' is not registered in SecuredTool registry.",
                "interceptor_response": None,
            }

        secured_tool: SecuredTool = self.tool_registry[tool_name]

        # Execute through AgentSentinel security control plane
        result = secured_tool.invoke(
            tool_input=tool_input,
            session_id=self.session_id,
            agent_id=self.agent_id,
            user_id=self.user_id,
            role=self.role,
            task_summary=task_summary,
            db=db,
            framework_name=self.framework_name,
        )

        return result
