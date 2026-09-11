"""
AgentSentinel Phase 0.5: Authoritative First-Class Tool Registry.
Centralizes tool metadata, capabilities, risk levels, approval requirements,
and sandbox profiles across the entire security control plane.
"""

from typing import Any, Callable, Dict, List, Optional
from app.core.logger import logger
from app.execution.config import execution_config
from app.execution.models import (
    AgentCapability,
    SensitivityLevel,
    ToolCategory,
    ToolDefinition,
)


class ToolRegistry:
    """
    Authoritative registry of all tools available in AgentSentinel.
    Provides canonical metadata, capability requirements, and runtime handlers.
    """

    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}
        self._seed_default_tools()

    def _seed_default_tools(self):
        """Seeds the standard AgentSentinel tool definitions."""
        # 1. Google Search
        self.register_tool(
            ToolDefinition(
                tool_id="google_search",
                name="google_search",
                description="Performs web search queries via authorized research domains.",
                category=ToolCategory.SEARCH,
                required_capability=AgentCapability.SEARCH,
                sensitivity=SensitivityLevel.LOW,
                risk_level="LOW",
                allowed_roles=["research_assistant", "research_coordinator", "research_worker", "code_assistant", "database_admin", "default_agent"],
                allowed_agent_capabilities=[AgentCapability.SEARCH],
                network_required=True,
                filesystem_required=False,
                process_execution_required=False,
                sandbox_required=False,
                approval_required=False,
                sandbox_profile_name="RESEARCH",
                metadata={"scope": "web_search"},
            ),
            handler=lambda query, limit=5: f"Search Results for '{query}': [1] FastAPI Security Best Practices, [2] Agent Runtime Isolation Guidelines.",
        )

        # 2. Read Workspace File
        self.register_tool(
            ToolDefinition(
                tool_id="read_workspace_file",
                name="read_workspace_file",
                description="Reads the contents of an authorized file within the workspace directory.",
                category=ToolCategory.FILESYSTEM,
                required_capability=AgentCapability.FILE_READ,
                sensitivity=SensitivityLevel.LOW,
                risk_level="LOW",
                allowed_roles=["research_assistant", "research_coordinator", "research_worker", "code_assistant", "database_admin", "default_agent"],
                allowed_agent_capabilities=[AgentCapability.FILE_READ],
                network_required=False,
                filesystem_required=True,
                process_execution_required=False,
                sandbox_required=False,
                approval_required=False,
                sandbox_profile_name="STANDARD",
                metadata={"scope": "workspace_read"},
            ),
            handler=lambda filepath: f"Workspace Content of {filepath}: {{'project': 'AgentSentinel', 'version': '0.1.0', 'status': 'active'}}",
        )

        # 3. Write Workspace File
        self.register_tool(
            ToolDefinition(
                tool_id="write_workspace_file",
                name="write_workspace_file",
                description="Writes content to a file strictly within the workspace directory boundary.",
                category=ToolCategory.FILESYSTEM,
                required_capability=AgentCapability.FILE_WRITE,
                sensitivity=SensitivityLevel.MEDIUM,
                risk_level="MEDIUM",
                allowed_roles=["code_assistant", "database_admin", "developer", "default_agent"],
                allowed_agent_capabilities=[AgentCapability.FILE_WRITE],
                network_required=False,
                filesystem_required=True,
                process_execution_required=False,
                sandbox_required=False,
                approval_required=False,
                sandbox_profile_name="STANDARD",
                metadata={"scope": "workspace_write"},
            ),
            handler=lambda filepath, content="": f"Successfully wrote {len(content)} bytes to workspace file {filepath}.",
        )

        # 4. Read System File (Credentials / OS Secrets)
        self.register_tool(
            ToolDefinition(
                tool_id="read_system_file",
                name="read_system_file",
                description="Attempts to read host system files or credential stores.",
                category=ToolCategory.CREDENTIAL,
                required_capability=AgentCapability.CREDENTIAL_ACCESS,
                sensitivity=SensitivityLevel.CRITICAL,
                risk_level="CRITICAL",
                allowed_roles=[],  # Prohibited by default for normal agents
                allowed_agent_capabilities=[AgentCapability.CREDENTIAL_ACCESS],
                network_required=False,
                filesystem_required=True,
                process_execution_required=False,
                sandbox_required=True,
                approval_required=True,
                sandbox_profile_name="STRICT",
                metadata={"scope": "system_credential_access"},
            ),
            handler=lambda filepath: f"System File Content of {filepath}: [PROTECTED_FILE_ACCESS_DENIED_OR_SIMULATED]",
        )

        # 5. Drop Database Table
        self.register_tool(
            ToolDefinition(
                tool_id="drop_database_table",
                name="drop_database_table",
                description="Drops a database table from the active schema. Requires administrator approval.",
                category=ToolCategory.DATABASE,
                required_capability=AgentCapability.DATABASE_WRITE,
                sensitivity=SensitivityLevel.CRITICAL,
                risk_level="HIGH",
                allowed_roles=["database_admin"],
                allowed_agent_capabilities=[AgentCapability.DATABASE_WRITE],
                network_required=False,
                filesystem_required=False,
                process_execution_required=False,
                sandbox_required=False,
                approval_required=True,
                sandbox_profile_name="PRIVILEGED",
                metadata={"scope": "database_schema_mutation"},
            ),
            handler=lambda table_name: f"Database table '{table_name}' dropped successfully.",
        )

        # 6. Execute Command (Subprocess)
        self.register_tool(
            ToolDefinition(
                tool_id="execute_command",
                name="execute_command",
                description="Executes a validated external executable from the allowed executable whitelist.",
                category=ToolCategory.PROCESS,
                required_capability=AgentCapability.PROCESS_EXECUTION,
                sensitivity=SensitivityLevel.HIGH,
                risk_level="HIGH",
                allowed_roles=["developer", "database_admin"],
                allowed_agent_capabilities=[AgentCapability.PROCESS_EXECUTION],
                network_required=False,
                filesystem_required=True,
                process_execution_required=True,
                sandbox_required=False,
                approval_required=False,
                sandbox_profile_name="DEVELOPER",
                metadata={"scope": "local_process_execution"},
            ),
            handler=lambda command, working_dir=None: f"Command execution completed: {command}",
        )

        # 7. Sandboxed Container Task (Docker Required)
        self.register_tool(
            ToolDefinition(
                tool_id="sandboxed_container_task",
                name="sandboxed_container_task",
                description="Runs an isolated task strictly inside a hardened Docker container sandbox.",
                category=ToolCategory.PROCESS,
                required_capability=AgentCapability.PROCESS_EXECUTION,
                sensitivity=SensitivityLevel.HIGH,
                risk_level="HIGH",
                allowed_roles=["developer", "database_admin"],
                allowed_agent_capabilities=[AgentCapability.PROCESS_EXECUTION],
                network_required=False,
                filesystem_required=True,
                process_execution_required=True,
                sandbox_required=True,
                approval_required=False,
                sandbox_profile_name="DEVELOPER",
                metadata={"scope": "container_sandbox", "docker_image": "python:3.11-slim"},
            ),
            handler=lambda task_input="": f"Container sandbox task finished: {task_input}",
        )

    def register_tool(self, tool_def: ToolDefinition, handler: Optional[Callable[..., Any]] = None):
        """Registers a new or updated tool definition."""
        if handler:
            tool_def.handler = handler
        self._tools[tool_def.tool_id] = tool_def
        logger.info(f"ToolRegistry: Registered tool '{tool_def.tool_id}' (Capability: {tool_def.required_capability.value})")

    def get_tool(self, tool_id: str) -> Optional[ToolDefinition]:
        """Retrieves a tool definition by tool ID or name."""
        return self._tools.get(tool_id)

    def list_tools(self, category: Optional[ToolCategory] = None, enabled_only: bool = True) -> List[ToolDefinition]:
        """Lists all registered tools, optionally filtered by category and active status."""
        tools = list(self._tools.values())
        if enabled_only:
            tools = [t for t in tools if t.enabled]
        if category:
            tools = [t for t in tools if t.category == category]
        return tools

    def disable_tool(self, tool_id: str) -> bool:
        """Disables a tool, immediately preventing any execution."""
        tool = self.get_tool(tool_id)
        if tool:
            tool.enabled = False
            logger.warning(f"ToolRegistry: Tool '{tool_id}' has been disabled.")
            return True
        return False

    def enable_tool(self, tool_id: str) -> bool:
        """Enables a tool."""
        tool = self.get_tool(tool_id)
        if tool:
            tool.enabled = True
            logger.info(f"ToolRegistry: Tool '{tool_id}' has been enabled.")
            return True
        return False


default_tool_registry = ToolRegistry()
