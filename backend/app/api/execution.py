"""
AgentSentinel Phase 0.5: Secure Execution & Tool Governance REST APIs.
Provides endpoints for tool registry management, sandbox profile inspection,
pre-execution validation, and secure tool execution through the gateway.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.logger import logger
from app.db.crud import get_execution_by_id, list_executions
from app.db.session import get_db
from app.execution.config import execution_config
from app.execution.gateway import default_execution_gateway
from app.execution.models import (
    AgentCapability,
    ExecutionContext,
    ExecutionOutput,
    ExecutionState,
    SandboxProfile,
    SensitivityLevel,
    ToolCategory,
    ToolDefinition,
)
from app.execution.registry import default_tool_registry

router = APIRouter(prefix="/api/v1", tags=["Execution & Tool Governance"])


# --- Pydantic Request / Response Schemas ---

class ToolCreateRequest(BaseModel):
    tool_id: str = Field(..., description="Unique tool identifier")
    name: str = Field(..., description="Canonical tool name")
    description: str = Field(..., description="Tool description and capabilities")
    category: ToolCategory = Field(ToolCategory.CUSTOM, description="Tool category")
    required_capability: AgentCapability = Field(..., description="Required agent capability")
    sensitivity: SensitivityLevel = Field(SensitivityLevel.LOW, description="Data sensitivity tier")
    risk_level: str = Field("LOW", description="Risk tier (LOW, MEDIUM, HIGH, CRITICAL)")
    allowed_roles: List[str] = Field(default_factory=list, description="Roles authorized to invoke this tool")
    allowed_agent_capabilities: List[AgentCapability] = Field(default_factory=list)
    network_required: bool = False
    filesystem_required: bool = False
    process_execution_required: bool = False
    sandbox_required: bool = False
    approval_required: bool = False
    sandbox_profile_name: str = "STANDARD"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ToolResponse(BaseModel):
    tool_id: str
    name: str
    description: str
    category: str
    required_capability: str
    sensitivity: str
    risk_level: str
    allowed_roles: List[str]
    allowed_agent_capabilities: List[str]
    network_required: bool
    filesystem_required: bool
    process_execution_required: bool
    sandbox_required: bool
    approval_required: bool
    enabled: bool
    version: str
    sandbox_profile_name: str
    metadata: Dict[str, Any]


class ExecutionValidateRequest(BaseModel):
    agent_id: str
    tool_id: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    delegation_id: Optional[str] = None
    approval_id: Optional[str] = None
    resource_scope: str = ""


class ExecutionValidateResponse(BaseModel):
    valid: bool
    reason: str
    tool_id: str
    agent_id: str
    sandbox_profile: str
    requires_approval: bool
    requires_sandbox: bool


class ExecutionRunRequest(BaseModel):
    session_id: str = Field(..., description="Session context ID")
    agent_id: str = Field(..., description="Executing agent ID")
    tool_id: str = Field(..., description="Target tool ID or name")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Tool invocation parameters")
    delegation_id: Optional[str] = Field(None, description="Delegation token if invoked under delegation")
    approval_id: Optional[str] = Field(None, description="Approval event ID if action was approved")
    resource_scope: str = Field("", description="Target resource identifier or path")
    timeout_seconds: float = Field(10.0, ge=0.1, le=60.0, description="Execution timeout bounding")


# --- Tool Registry Endpoints ---

@router.get("/tools", response_model=List[ToolResponse])
def list_tools():
    """Lists all registered tools and their governance policies."""
    tools = default_tool_registry.list_tools()
    return [
        ToolResponse(
            tool_id=t.tool_id,
            name=t.name,
            description=t.description,
            category=t.category.value,
            required_capability=t.required_capability.value,
            sensitivity=t.sensitivity.value,
            risk_level=t.risk_level,
            allowed_roles=t.allowed_roles,
            allowed_agent_capabilities=[c.value for c in t.allowed_agent_capabilities],
            network_required=t.network_required,
            filesystem_required=t.filesystem_required,
            process_execution_required=t.process_execution_required,
            sandbox_required=t.sandbox_required,
            approval_required=t.approval_required,
            enabled=t.enabled,
            version=t.version,
            sandbox_profile_name=t.sandbox_profile_name,
            metadata=t.metadata,
        )
        for t in tools
    ]


@router.post("/tools", response_model=ToolResponse, status_code=status.HTTP_201_CREATED)
def register_tool(payload: ToolCreateRequest):
    """Registers a new tool into the authoritative Tool Registry."""
    tool_def = ToolDefinition(
        tool_id=payload.tool_id,
        name=payload.name,
        description=payload.description,
        category=payload.category,
        required_capability=payload.required_capability,
        sensitivity=payload.sensitivity,
        risk_level=payload.risk_level,
        allowed_roles=payload.allowed_roles,
        allowed_agent_capabilities=payload.allowed_agent_capabilities or [payload.required_capability],
        network_required=payload.network_required,
        filesystem_required=payload.filesystem_required,
        process_execution_required=payload.process_execution_required,
        sandbox_required=payload.sandbox_required,
        approval_required=payload.approval_required,
        sandbox_profile_name=payload.sandbox_profile_name,
        metadata=payload.metadata,
    )
    registered = default_tool_registry.register_tool(tool_def)
    return ToolResponse(
        tool_id=registered.tool_id,
        name=registered.name,
        description=registered.description,
        category=registered.category.value,
        required_capability=registered.required_capability.value,
        sensitivity=registered.sensitivity.value,
        risk_level=registered.risk_level,
        allowed_roles=registered.allowed_roles,
        allowed_agent_capabilities=[c.value for c in registered.allowed_agent_capabilities],
        network_required=registered.network_required,
        filesystem_required=registered.filesystem_required,
        process_execution_required=registered.process_execution_required,
        sandbox_required=registered.sandbox_required,
        approval_required=registered.approval_required,
        enabled=registered.enabled,
        version=registered.version,
        sandbox_profile_name=registered.sandbox_profile_name,
        metadata=registered.metadata,
    )


@router.get("/tools/{tool_id}", response_model=ToolResponse)
def get_tool(tool_id: str):
    """Retrieves tool governance metadata by tool ID or name."""
    tool = default_tool_registry.get_tool(tool_id)
    if not tool:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tool '{tool_id}' is not registered in Tool Registry.",
        )
    return ToolResponse(
        tool_id=tool.tool_id,
        name=tool.name,
        description=tool.description,
        category=tool.category.value,
        required_capability=tool.required_capability.value,
        sensitivity=tool.sensitivity.value,
        risk_level=tool.risk_level,
        allowed_roles=tool.allowed_roles,
        allowed_agent_capabilities=[c.value for c in tool.allowed_agent_capabilities],
        network_required=tool.network_required,
        filesystem_required=tool.filesystem_required,
        process_execution_required=tool.process_execution_required,
        sandbox_required=tool.sandbox_required,
        approval_required=tool.approval_required,
        enabled=tool.enabled,
        version=tool.version,
        sandbox_profile_name=tool.sandbox_profile_name,
        metadata=tool.metadata,
    )


@router.post("/tools/{tool_id}/disable")
def disable_tool(tool_id: str):
    """Disables a tool immediately, blocking any future executions."""
    disabled = default_tool_registry.disable_tool(tool_id)
    if not disabled:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tool '{tool_id}' not found.",
        )
    return {"message": f"Tool '{tool_id}' disabled successfully.", "status": "DISABLED"}


# --- Sandbox Profiles Endpoint ---

@router.get("/sandbox/profiles", response_model=Dict[str, Any])
def list_sandbox_profiles():
    """Returns available sandbox profiles and their isolation boundaries."""
    return {
        name: {
            "mode": prof.mode.value,
            "network_allowed": prof.network_allowed,
            "allowed_domains": prof.allowed_domains,
            "blocked_domains": prof.blocked_domains,
            "process_execution_allowed": prof.process_execution_allowed,
            "allowed_executables": prof.allowed_executables,
            "readable_paths": prof.readable_paths,
            "writable_paths": prof.writable_paths,
            "max_timeout_seconds": prof.max_timeout_seconds,
            "max_memory_mb": prof.max_memory_mb,
            "max_output_bytes": prof.max_output_bytes,
            "docker_image": prof.docker_image,
        }
        for name, prof in execution_config.SANDBOX_PROFILES.items()
    }


# --- Execution Endpoints ---

@router.post("/execution/validate", response_model=ExecutionValidateResponse)
def validate_execution(payload: ExecutionValidateRequest, db: Session = Depends(get_db)):
    """Pre-validates whether an agent would be permitted to execute a tool."""
    tool = default_tool_registry.get_tool(payload.tool_id)
    if not tool:
        return ExecutionValidateResponse(
            valid=False,
            reason=f"Tool '{payload.tool_id}' is not registered in Tool Registry.",
            tool_id=payload.tool_id,
            agent_id=payload.agent_id,
            sandbox_profile="NONE",
            requires_approval=False,
            requires_sandbox=False,
        )

    if not tool.enabled:
        return ExecutionValidateResponse(
            valid=False,
            reason=f"Tool '{tool.name}' is currently disabled.",
            tool_id=tool.tool_id,
            agent_id=payload.agent_id,
            sandbox_profile=tool.sandbox_profile_name,
            requires_approval=tool.approval_required,
            requires_sandbox=tool.sandbox_required,
        )

    return ExecutionValidateResponse(
        valid=True,
        reason="Tool execution parameters valid under registered policy.",
        tool_id=tool.tool_id,
        agent_id=payload.agent_id,
        sandbox_profile=tool.sandbox_profile_name,
        requires_approval=tool.approval_required,
        requires_sandbox=tool.sandbox_required,
    )


@router.post("/execution/run", response_model=Dict[str, Any])
def run_execution(payload: ExecutionRunRequest, db: Session = Depends(get_db)):
    """
    Executes an authorized tool strictly through the SecureExecutionGateway.
    Enforces all 14 execution checks, profile sandboxing, and output secret redaction.
    """
    context = ExecutionContext(
        execution_id=f"exec_{uuid_short()}",
        agent_id=payload.agent_id,
        delegation_id=payload.delegation_id,
        session_id=payload.session_id,
        tool_id=payload.tool_id,
        tool_name=payload.tool_id,
        arguments=payload.arguments,
        resource_scope=payload.resource_scope,
        approval_id=payload.approval_id,
        approval_event_id=payload.approval_id,
        timeout_seconds=payload.timeout_seconds,
    )

    output: ExecutionOutput = default_execution_gateway.execute(context=context, db=db)

    return {
        "execution_id": output.execution_id,
        "status": output.status.value,
        "output": output.sanitized_output,
        "exit_code": output.exit_code,
        "execution_time_ms": output.execution_time_ms,
        "execution_backend": output.execution_backend.value,
        "redacted": output.redacted,
        "detected_secrets": output.detected_secrets,
        "error_message": output.error_message,
        "metadata": output.metadata,
    }


@router.get("/execution/{execution_id}", response_model=Dict[str, Any])
def get_execution_record(execution_id: str, db: Session = Depends(get_db)):
    """Retrieves durable execution audit record from PostgreSQL."""
    rec = get_execution_by_id(db, execution_id)
    if not rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Execution record '{execution_id}' not found.",
        )
    return {
        "execution_id": rec.execution_id,
        "session_id": rec.session_id,
        "agent_id": rec.agent_id,
        "tool_name": rec.tool_name,
        "status": rec.status,
        "execution_backend": rec.execution_backend,
        "sandbox_profile": rec.sandbox_profile,
        "execution_time_ms": rec.execution_time_ms,
        "exit_code": rec.exit_code,
        "redacted": rec.redacted,
        "detected_secrets": rec.detected_secrets_json,
        "error_message": rec.error_message,
        "sanitized_output_preview": rec.sanitized_output_preview,
        "created_at": rec.created_at.isoformat() if rec.created_at else None,
    }


@router.get("/executions", response_model=List[Dict[str, Any]])
def list_execution_records(
    session_id: Optional[str] = Query(None),
    agent_id: Optional[str] = Query(None),
    tool_name: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """Lists recent tool execution audit records with optional filters."""
    records = list_executions(
        db,
        session_id=session_id,
        agent_id=agent_id,
        tool_name=tool_name,
        status=status,
        limit=limit,
    )
    return [
        {
            "execution_id": r.execution_id,
            "session_id": r.session_id,
            "agent_id": r.agent_id,
            "tool_name": r.tool_name,
            "status": r.status,
            "execution_backend": r.execution_backend,
            "sandbox_profile": r.sandbox_profile,
            "execution_time_ms": r.execution_time_ms,
            "exit_code": r.exit_code,
            "redacted": r.redacted,
            "detected_secrets": r.detected_secrets_json,
            "error_message": r.error_message,
            "sanitized_output_preview": r.sanitized_output_preview,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in records
    ]


def uuid_short() -> str:
    import uuid
    return uuid.uuid4().hex[:10]
