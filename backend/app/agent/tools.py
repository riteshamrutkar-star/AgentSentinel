from typing import Any, Callable, Dict, Optional
from sqlalchemy.orm import Session
from app.interceptor.proxy import intercept_tool_call
from app.interceptor.schema import InterceptorResponse, ToolCallRequest

# --- Base Underlying Tool Functions ---

def fn_google_search(query: str, limit: int = 5) -> str:
    """Mock implementation of Google Search tool."""
    return f"Search Results for '{query}': [1] FastAPI Security Best Practices, [2] Agent Runtime Isolation Guidelines."

def fn_read_workspace_file(filepath: str) -> str:
    """Mock implementation of workspace file read tool."""
    return f"Workspace Content of {filepath}: {{'project': 'AgentSentinel', 'version': '0.1.0', 'status': 'active'}}"

def fn_read_system_file(filepath: str) -> str:
    """Mock implementation of system file read tool."""
    return f"System File Content of {filepath}: SSH-PRIVATE-KEY-SECRET-DATA"

def fn_drop_database_table(table_name: str) -> str:
    """Mock implementation of database table drop tool."""
    return f"Database table '{table_name}' dropped successfully."

def fn_write_workspace_file(filepath: str, content: str = "") -> str:
    """Mock implementation of workspace file write tool."""
    return f"Successfully wrote {len(content)} bytes to workspace file {filepath}."

# --- Secured Tool Wrapper Class ---

class SecuredTool:
    """
    Wraps standard tool functions or LangChain Tool instances with AgentSentinel runtime mediation.
    Mediates every tool call through the interceptor, policy engine, anomaly detector, and audit subsystem.
    """

    def __init__(
        self,
        name: str,
        func: Callable[..., str],
        description: str,
        action_type: str = "UNKNOWN",
        target_resource: str = "",
    ):
        self.name = name
        self.func = func
        self.description = description
        self.action_type = action_type
        self.target_resource = target_resource

    def invoke(
        self,
        tool_input: Dict[str, Any],
        session_id: str,
        agent_id: str,
        user_id: str,
        role: str,
        task_summary: str,
        db: Session,
        framework_name: str = "LangChain",
    ) -> Dict[str, Any]:
        """
        Mediates the tool call through AgentSentinel prior to execution.
        Executes underlying function ONLY when verdict is ALLOW.
        """
        # Determine target resource from arguments if not statically defined
        resource = self.target_resource
        if not resource:
            resource = str(tool_input.get("filepath", tool_input.get("table_name", tool_input.get("query", ""))))

        # 1. Build raw ToolCallRequest
        request = ToolCallRequest(
            session_id=session_id,
            agent_id=agent_id,
            user_id=user_id,
            tool_name=self.name,
            arguments=tool_input,
            role=role,
            framework_name=framework_name,
            target_resource=resource,
            action_type=self.action_type,
            task_summary=task_summary,
        )

        # 2. Mediate through AgentSentinel runtime security control plane
        response: InterceptorResponse = intercept_tool_call(request, db)

        # 3. Enforce execution control verdict
        if response.decision == "ALLOW":
            try:
                output = self.func(**tool_input)
            except Exception as e:
                output = f"Tool Execution Error: {str(e)}"

            return {
                "status": "SUCCESS",
                "verdict": response.decision,
                "execution_allowed": True,
                "output": output,
                "interceptor_response": response.model_dump(),
            }

        elif response.decision == "REQUIRE_APPROVAL":
            return {
                "status": "PAUSED_FOR_APPROVAL",
                "verdict": response.decision,
                "execution_allowed": False,
                "output": f"SECURITY VERDICT: REQUIRE_APPROVAL. Action '{self.name}' requires human administrator sign-off. Event ID: {response.event_id}",
                "interceptor_response": response.model_dump(),
            }

        else: # BLOCK
            return {
                "status": "BLOCKED",
                "verdict": response.decision,
                "execution_allowed": False,
                "output": f"SECURITY VERDICT: BLOCK. Action '{self.name}' prohibited by AgentSentinel security policy. Reason: {response.decision_reason}",
                "interceptor_response": response.model_dump(),
            }

def get_secured_tool_registry() -> Dict[str, SecuredTool]:
    """Returns registry of standard AgentSentinel SecuredTools."""
    return {
        "google_search": SecuredTool(
            name="google_search",
            func=fn_google_search,
            description="Performs web search query",
            action_type="NETWORK",
        ),
        "read_workspace_file": SecuredTool(
            name="read_workspace_file",
            func=fn_read_workspace_file,
            description="Reads workspace file content",
            action_type="READ",
        ),
        "read_system_file": SecuredTool(
            name="read_system_file",
            func=fn_read_system_file,
            description="Reads system or protected filepath",
            action_type="READ",
        ),
        "drop_database_table": SecuredTool(
            name="drop_database_table",
            func=fn_drop_database_table,
            description="Drops database table from schema",
            action_type="DATABASE",
        ),
        "write_workspace_file": SecuredTool(
            name="write_workspace_file",
            func=fn_write_workspace_file,
            description="Writes content to workspace file",
            action_type="WRITE",
        ),
    }
