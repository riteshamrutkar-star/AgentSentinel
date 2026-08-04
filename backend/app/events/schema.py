from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

# --- Enums for Strict Typing & Explainability ---

class ActionType(str, Enum):
    READ = "READ"
    WRITE = "WRITE"
    EXECUTE = "EXECUTE"
    NETWORK = "NETWORK"
    DATABASE = "DATABASE"
    UNKNOWN = "UNKNOWN"

class ExecutionStage(str, Enum):
    PRE_EXECUTION = "PRE_EXECUTION"
    POST_EXECUTION = "POST_EXECUTION"
    TERMINATED = "TERMINATED"

class SensitivityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class PolicyResult(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    FLAG_ONLY = "FLAG_ONLY"

class ApprovalStatus(str, Enum):
    NOT_REQUIRED = "NOT_REQUIRED"
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"

# --- Sub-Schemas for Category Groupings ---

class IdentityContext(BaseModel):
    event_id: str = Field(..., description="Unique UUID for this security event")
    session_id: str = Field(..., description="Agent session identifier")
    agent_id: str = Field(..., description="Unique ID of the AI Agent")
    user_id: str = Field(..., description="ID of human user initiating the session")
    role: str = Field("default_agent", description="Security role assigned to agent")
    framework_name: str = Field("LangChain", description="Framework powering the agent (e.g. LangChain, AutoGen)")

class TaskContext(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="ISO 8601 UTC timestamp")
    task_summary: str = Field("", description="High-level summary of the overall agent task")
    prompt_context_summary: str = Field("", description="Summarized prompt history context")
    session_state: str = Field("ACTIVE", description="Current state of session (ACTIVE, SUSPENDED, COMPLETED)")
    previous_action_count: int = Field(0, description="Total tool actions performed in current session")
    recent_tool_history: List[str] = Field(default_factory=list, description="Recent tools called in this session")

class ToolActionContext(BaseModel):
    tool_name: str = Field(..., description="Name of the invoked tool")
    action_type: ActionType = Field(ActionType.UNKNOWN, description="Category of tool action")
    target_resource: str = Field("", description="Target URI, filepath, host, or resource")
    arguments_payload: Dict[str, Any] = Field(default_factory=dict, description="Raw tool call parameters")
    source_module: str = Field("agent.tools", description="Source code module invoking the tool")
    execution_stage: ExecutionStage = Field(ExecutionStage.PRE_EXECUTION, description="Current lifecycle stage")

class SecurityContext(BaseModel):
    permission_level: str = Field("USER", description="Required permission scope (e.g., READ_ONLY, ADMIN)")
    policy_tags: List[str] = Field(default_factory=list, description="Applied security policy tags")
    sensitivity_level: SensitivityLevel = Field(SensitivityLevel.LOW, description="Data sensitivity risk classification")
    risk_indicators: List[str] = Field(default_factory=list, description="Triggered security heuristic indicators")
    anomaly_score: float = Field(0.0, description="Calculated statistical anomaly score (0.0 - 1.0)")
    threat_flags: List[str] = Field(default_factory=list, description="Identified threat categories (e.g. PROMPT_INJECTION, DATA_EXFILTRATION)")

class DecisionContext(BaseModel):
    policy_result: PolicyResult = Field(PolicyResult.ALLOW, description="Policy engine evaluation decision")
    decision_result: str = Field("ALLOW", description="Final verdict applied to tool execution")
    decision_reason: str = Field("Passed standard permission checks", description="Human-readable decision explanation")
    approval_required: bool = Field(False, description="Whether human approval is required before execution")
    reviewer: Optional[str] = Field(None, description="Identifier of human reviewer if approval was requested")
    approval_status: ApprovalStatus = Field(ApprovalStatus.NOT_REQUIRED, description="Current state of human review")

class ExecutionContext(BaseModel):
    execution_allowed: bool = Field(True, description="True if tool execution was permitted")
    execution_result: Optional[Dict[str, Any]] = Field(None, description="Serialized tool execution return data")
    latency_ms: float = Field(0.0, description="Total execution latency in milliseconds")
    error_message: Optional[str] = Field(None, description="Error message if execution failed")
    retry_count: int = Field(0, description="Number of execution retry attempts")

class AuditContext(BaseModel):
    log_status: str = Field("RECORDED", description="Status of audit record logging")
    is_stored: bool = Field(False, description="Whether event is persisted in database")
    trace_id: str = Field("", description="Distributed tracing ID")
    correlation_id: str = Field("", description="Session correlation ID across microservices")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional arbitrary metadata key-values")

# --- Top-Level Unified Security Event Schema ---

class SecurityEventSchema(BaseModel):
    """Complete Security Event model representing an intercepted AI-agent tool action."""
    identity: IdentityContext
    task_context: TaskContext
    tool_action: ToolActionContext
    security_context: SecurityContext
    decision_context: DecisionContext
    execution_context: ExecutionContext
    audit_context: AuditContext
