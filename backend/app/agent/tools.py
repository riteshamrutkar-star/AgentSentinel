import uuid
from typing import Any, Callable, Dict, Optional
from sqlalchemy.orm import Session
from app.interceptor.proxy import intercept_tool_call
from app.interceptor.schema import InterceptorResponse, ToolCallRequest
from app.execution import (
    default_execution_gateway,
    default_tool_registry,
    ExecutionContext,
    ExecutionState,
    ToolCategory,
    ToolDefinition,
)
from app.multiagent.models import AgentCapability, AgentIdentity, AgentStatus, TrustLevel
from app.multiagent.registry import default_agent_registry

# --- Base Underlying Tool Functions ---

def fn_google_search(query: str, limit: int = 5) -> str:
    """Mock implementation of Google Search tool."""
    return f"Search Results for '{query}': [1] FastAPI Security Best Practices, [2] Agent Runtime Isolation Guidelines."

def fn_read_workspace_file(filepath: str) -> str:
    """Mock implementation of workspace file read tool."""
    return f"Workspace Content of {filepath}: {{'project': 'AgentSentinel', 'version': '0.1.0', 'status': 'active'}}"

def fn_read_system_file(filepath: str) -> str:
    """Mock implementation of system file read tool with sanitized simulated output."""
    return f"System File Content of {filepath}: [PROTECTED_FILE_ACCESS_DENIED_OR_SIMULATED]"

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
    Enforces strict fail-closed security: the tool function NEVER executes unless explicitly ALLOWed.
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

        # Ensure tool is registered in authoritative ToolRegistry
        existing = default_tool_registry.get_tool(name)
        if not existing:
            cat_map = {
                "NETWORK": (ToolCategory.NETWORK, AgentCapability.SEARCH, "RESEARCH"),
                "READ": (ToolCategory.FILESYSTEM, AgentCapability.FILE_READ, "STANDARD"),
                "WRITE": (ToolCategory.FILESYSTEM, AgentCapability.FILE_WRITE, "STANDARD"),
                "DATABASE": (ToolCategory.DATABASE, AgentCapability.DATABASE_WRITE, "PRIVILEGED"),
                "PROCESS": (ToolCategory.PROCESS, AgentCapability.PROCESS_EXECUTION, "DEVELOPER"),
                "SHELL": (ToolCategory.PROCESS, AgentCapability.PROCESS_EXECUTION, "DEVELOPER"),
            }
            cat, cap, prof = cat_map.get(action_type, (ToolCategory.CUSTOM, AgentCapability.SEARCH, "STANDARD"))
            tool_def = ToolDefinition(
                tool_id=name,
                name=name,
                description=description,
                category=cat,
                required_capability=cap,
                allowed_roles=["research_assistant", "research_coordinator", "research_worker", "code_assistant", "database_admin", "developer", "default_agent"],
                allowed_agent_capabilities=[cap],
                network_required=(action_type == "NETWORK"),
                filesystem_required=(action_type in ("READ", "WRITE")),
                process_execution_required=(action_type in ("PROCESS", "SHELL")),
                sandbox_profile_name=prof,
            )
            default_tool_registry.register_tool(tool_def, handler=func)

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
        Executes underlying function ONLY when verdict is explicitly ALLOW.
        Fails closed on any unexpected evaluation or database errors.
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

        # 2. Mediate through AgentSentinel runtime security control plane with fail-closed guarantee
        try:
            response: InterceptorResponse = intercept_tool_call(request, db)
        except Exception as e:
            return {
                "status": "BLOCKED",
                "verdict": "BLOCK",
                "execution_allowed": False,
                "output": "SECURITY VERDICT: BLOCK. Action prohibited due to security interception error.",
                "interceptor_response": None,
            }

        # 3. Enforce execution control verdict via mandatory SecureExecutionGateway
        if response.decision == "ALLOW" and response.execution_allowed:
            # Ensure agent is registered in AgentRegistry
            agent = default_agent_registry.get_agent(agent_id, db=db)
            if not agent:
                agent = AgentIdentity(
                    agent_id=agent_id,
                    name=f"Agent-{agent_id}",
                    role=role,
                    agent_type="worker",
                    owner="system",
                    capabilities=[
                        AgentCapability.SEARCH,
                        AgentCapability.FILE_READ,
                        AgentCapability.FILE_WRITE,
                        AgentCapability.DATABASE_READ,
                        AgentCapability.DATABASE_WRITE,
                        AgentCapability.PROCESS_EXECUTION,
                        AgentCapability.DELEGATION,
                    ],
                    trust_level=TrustLevel.STANDARD,
                    trust_score=0.75,
                    status=AgentStatus.ACTIVE,
                )
                default_agent_registry.register_agent(agent, db=db)

            exec_ctx = ExecutionContext(
                execution_id=f"exec_{uuid.uuid4().hex[:10]}",
                agent_id=agent_id,
                session_id=session_id,
                tool_id=self.name,
                tool_name=self.name,
                arguments=tool_input,
                capabilities=agent.capabilities if agent else [],
                resource_scope=resource,
                policy_decision=response.decision,
                approval_id=response.event_id,
                approval_event_id=response.event_id,
                timeout_seconds=10.0,
            )

            # Route through SecureExecutionGateway
            exec_res = default_execution_gateway.execute(exec_ctx, handler=self.func, db=db)

            if exec_res.status == ExecutionState.COMPLETED:
                return {
                    "status": "SUCCESS",
                    "verdict": response.decision,
                    "execution_allowed": True,
                    "output": exec_res.sanitized_output,
                    "interceptor_response": response.model_dump(),
                    "execution_id": exec_res.execution_id,
                    "execution_time_ms": exec_res.execution_time_ms,
                    "execution_backend": exec_res.execution_backend.value,
                }
            else:
                return {
                    "status": "BLOCKED",
                    "verdict": "BLOCK",
                    "execution_allowed": False,
                    "output": f"SECURITY VERDICT: BLOCK. Action '{self.name}' failed execution sandbox check. Reason: {exec_res.error_message or exec_res.sanitized_output}",
                    "interceptor_response": response.model_dump(),
                    "execution_id": exec_res.execution_id,
                }

        elif response.decision == "REQUIRE_APPROVAL":
            return {
                "status": "PAUSED_FOR_APPROVAL",
                "verdict": response.decision,
                "execution_allowed": False,
                "output": f"SECURITY VERDICT: REQUIRE_APPROVAL. Action '{self.name}' requires human administrator sign-off. Event ID: {response.event_id}",
                "interceptor_response": response.model_dump(),
            }

        else: # BLOCK or any unrecognized state
            return {
                "status": "BLOCKED",
                "verdict": "BLOCK",
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
