from datetime import datetime, timezone
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

class ToolCallRequest(BaseModel):
    """Raw tool invocation payload submitted by an AI Agent or SDK wrapper."""
    session_id: str = Field(..., description="Agent session identifier")
    agent_id: str = Field(..., description="Unique agent identifier")
    user_id: str = Field(..., description="Human user identifier")
    tool_name: str = Field(..., description="Name of the tool being called")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Raw tool call parameter payload")
    role: str = Field("default_agent", description="Security role assigned to agent")
    framework_name: str = Field("LangChain", description="Framework powering the agent")
    target_resource: Optional[str] = Field("", description="Target URI, filepath, or host")
    action_type: Optional[str] = Field("UNKNOWN", description="Action category (READ, WRITE, EXECUTE, NETWORK, DATABASE)")
    task_summary: Optional[str] = Field("", description="High-level goal summary of current agent task")
    prompt_context_summary: Optional[str] = Field("", description="Summarized prompt history context")

class InterceptorResponse(BaseModel):
    """Structured security verdict returned by AgentSentinel Runtime Proxy."""
    event_id: str = Field(..., description="Unique security event UUID")
    decision: str = Field(..., description="Security verdict: ALLOW, BLOCK, or REQUIRE_APPROVAL")
    decision_reason: str = Field(..., description="Human-readable decision explanation")
    approval_required: bool = Field(False, description="True if human authorization is required before execution")
    execution_allowed: bool = Field(True, description="True if agent is permitted to execute tool")
    latency_ms: float = Field(0.0, description="Total interception and security evaluation latency in ms")
    stored: bool = Field(True, description="True if event is recorded in PostgreSQL database")
    trace_id: str = Field(..., description="Distributed tracing ID")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="ISO UTC timestamp")
