"""
AgentSentinel Phase 0.5: Secure Execution, Sandboxing & Tool Governance Domain Models.
Defines Tool Definitions, Execution Contexts, Sandbox Profiles, Execution States,
Output Security results, and Security Enums.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set
from pydantic import BaseModel, Field

from app.multiagent.models import AgentCapability


def utc_now() -> datetime:
    """Returns the current UTC datetime."""
    return datetime.now(timezone.utc)


class ToolCategory(str, Enum):
    SEARCH = "SEARCH"
    FILESYSTEM = "FILESYSTEM"
    DATABASE = "DATABASE"
    NETWORK = "NETWORK"
    PROCESS = "PROCESS"
    CREDENTIAL = "CREDENTIAL"
    SYSTEM = "SYSTEM"
    CUSTOM = "CUSTOM"


class SensitivityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ExecutionState(str, Enum):
    REQUESTED = "REQUESTED"
    VALIDATED = "VALIDATED"
    BLOCKED = "BLOCKED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"


class SandboxMode(str, Enum):
    STRICT = "STRICT"
    STANDARD = "STANDARD"
    RESEARCH = "RESEARCH"
    DEVELOPER = "DEVELOPER"
    PRIVILEGED = "PRIVILEGED"


class ExecutionBackend(str, Enum):
    IN_PROCESS_GUARDED = "IN_PROCESS_GUARDED"
    DOCKER = "DOCKER"


class SandboxProfile(BaseModel):
    """Configuration for execution isolation boundary."""
    name: str = "STANDARD"
    mode: SandboxMode = SandboxMode.STANDARD
    readable_paths: List[str] = Field(default_factory=list)
    writable_paths: List[str] = Field(default_factory=list)
    network_allowed: bool = False
    allowed_domains: List[str] = Field(default_factory=list)
    blocked_domains: List[str] = Field(default_factory=list)
    process_execution_allowed: bool = False
    allowed_executables: List[str] = Field(default_factory=list)
    max_timeout_seconds: float = 10.0
    max_memory_mb: int = 256
    max_output_bytes: int = 1_048_576  # 1 MB
    cpu_shares: int = 1024
    docker_image: Optional[str] = None


class ToolDefinition(BaseModel):
    """Authoritative metadata and governance policy for an execution tool."""
    tool_id: str
    name: str
    description: str
    category: ToolCategory
    required_capability: AgentCapability
    sensitivity: SensitivityLevel = SensitivityLevel.LOW
    risk_level: str = "LOW"
    allowed_roles: List[str] = Field(default_factory=list)
    allowed_agent_capabilities: List[AgentCapability] = Field(default_factory=list)
    network_required: bool = False
    filesystem_required: bool = False
    process_execution_required: bool = False
    sandbox_required: bool = False
    approval_required: bool = False
    enabled: bool = True
    version: str = "1.0.0"
    sandbox_profile_name: str = "STANDARD"
    metadata: Dict[str, Any] = Field(default_factory=dict)
    # The actual implementation callable (kept in memory, excluded from serialization)
    handler: Optional[Callable[..., Any]] = Field(default=None, exclude=True)


class ExecutionContext(BaseModel):
    """
    Immutable authorization and security execution context.
    Binds the tool call to an authorized agent, delegation context, and sandbox profile.
    """
    execution_id: str
    agent_id: str
    origin_agent_id: Optional[str] = None
    delegation_id: Optional[str] = None
    session_id: str
    tool_id: str
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    capabilities: List[AgentCapability] = Field(default_factory=list)
    approved_capabilities: List[AgentCapability] = Field(default_factory=list)
    resource_scope: str = ""
    risk_score: float = 0.0
    policy_decision: str = "ALLOW"
    approval_id: Optional[str] = None
    approval_event_id: Optional[str] = None
    sandbox_profile: SandboxProfile = Field(default_factory=SandboxProfile)
    execution_backend: ExecutionBackend = ExecutionBackend.IN_PROCESS_GUARDED
    timeout_seconds: float = 10.0
    created_at: datetime = Field(default_factory=utc_now)


class SecretRedactionResult(BaseModel):
    """Result of scanning text for sensitive secret leakage."""
    sanitized_text: str
    redacted: bool = False
    detected_secrets: List[str] = Field(default_factory=list)


class ExecutionOutput(BaseModel):
    """Structured, security-sanitized result of a tool execution."""
    execution_id: str
    status: ExecutionState
    raw_output: Optional[str] = Field(default=None, exclude=True)  # Kept in memory only
    sanitized_output: str = ""
    exit_code: int = 0
    execution_time_ms: float = 0.0
    execution_backend: ExecutionBackend = ExecutionBackend.IN_PROCESS_GUARDED
    redacted: bool = False
    detected_secrets: List[str] = Field(default_factory=list)
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
