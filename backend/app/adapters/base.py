"""
AgentSentinel Phase 0.9: Canonical Ecosystem Adapter Architecture.
Provides the base adapter interface, canonical security request/result models,
and SecurityBlockedException for AI agent ecosystem integrations.

STATUS CLASSIFICATIONS:
- SUPPORTED: Fully implemented, tested, canonical translation, security enforcement, audit.
- EXPERIMENTAL: Partial implementation, prototype integration.
- NOT_IMPLEMENTED: Architecture placeholder, pending external library integration.
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.interceptor.proxy import intercept_tool_call
from app.interceptor.schema import ToolCallRequest, InterceptorResponse
from app.db.session import SessionLocal


class AdapterStatus(str, Enum):
    SUPPORTED = "SUPPORTED"
    EXPERIMENTAL = "EXPERIMENTAL"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"


class CanonicalSecurityRequest(BaseModel):
    """Normalized security request model shared across all framework adapters."""
    agent_id: str = Field(..., description="Unique agent identifier")
    session_id: str = Field(..., description="Active session identifier")
    tool_name: str = Field(..., description="Name of tool requested for invocation")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Tool invocation parameters")
    framework_name: str = Field(..., description="Originating AI agent framework")
    framework_version: Optional[str] = Field(None, description="Framework software version")
    namespace: str = Field("default", description="Durable tenant or environment namespace")
    capability: str = Field("DEFAULT", description="Requested tool capability tier")
    user_id: str = Field("default_user", description="Human user or tenant identifier")
    role: str = Field("default_agent", description="Security role assigned to agent")
    task_summary: str = Field("", description="High-level task goal")
    prompt_context_summary: str = Field("", description="Summarized context window")
    target_resource: Optional[str] = Field("", description="Target URL, path, or resource identifier")
    action_type: Optional[str] = Field("EXECUTE", description="Action category (READ, WRITE, EXECUTE, NETWORK)")
    delegation_id: Optional[str] = Field(None, description="Active delegation token ID")


class CanonicalSecurityResult(BaseModel):
    """Normalized security evaluation result returned to frameworks."""
    allowed: bool
    decision: str  # "ALLOW", "BLOCK", "REQUIRE_APPROVAL"
    decision_reason: str
    event_id: str
    trace_id: str
    approval_required: bool
    execution_allowed: bool
    latency_ms: float
    namespace: str
    threat_flags: List[str] = Field(default_factory=list)


class SecurityBlockedException(Exception):
    """
    Raised by framework adapters when AgentSentinel denies or blocks a tool invocation.
    Prevents unauthorized or high-risk tool execution in the host agent framework.
    """

    def __init__(self, message: str, result: Optional[CanonicalSecurityResult] = None):
        super().__init__(message)
        self.result = result
        self.decision = result.decision if result else "BLOCK"
        self.event_id = result.event_id if result else None
        self.reason = result.decision_reason if result else message
        self.execution_allowed = result.execution_allowed if result else False


class AgentSentinelAdapter(ABC):
    """Abstract base class for framework security adapters."""

    @property
    @abstractmethod
    def framework_name(self) -> str:
        """Name of the integrated agent framework."""
        pass

    @property
    @abstractmethod
    def status(self) -> AdapterStatus:
        """Supported status of this adapter."""
        pass

    def evaluate_request(self, request: CanonicalSecurityRequest) -> CanonicalSecurityResult:
        """
        Feeds canonical request directly into AgentSentinel's core runtime interceptor.
        Executes within database transaction with rollback protection.
        """
        from app.interceptor.proxy import evaluate_canonical_request
        from app.core.canonical import canonical_decision_to_adapter_result

        db = SessionLocal()
        try:
            decision = evaluate_canonical_request(request, db)
            return canonical_decision_to_adapter_result(decision)
        except Exception as e:
            logger.error(f"AgentSentinelAdapter [{self.framework_name}]: Error evaluating request: {e}", exc_info=True)
            sanitized_reason = "Security evaluation failed closed due to an internal control plane error."
            return CanonicalSecurityResult(
                allowed=False,
                decision="BLOCK",
                decision_reason=sanitized_reason,
                event_id="evt_internal_error",
                trace_id="",
                approval_required=False,
                execution_allowed=False,
                latency_ms=0.0,
                namespace=request.namespace,
            )
        finally:
            db.close()

    def enforce(self, request: CanonicalSecurityRequest) -> CanonicalSecurityResult:
        """
        Evaluates security policies and raises SecurityBlockedException if verdict is not ALLOW.
        """
        result = self.evaluate_request(request)
        if not result.allowed:
            raise SecurityBlockedException(
                f"AgentSentinel Security Blocked [{self.framework_name}]: {result.decision_reason} (Event: {result.event_id})",
                result=result,
            )
        return result
