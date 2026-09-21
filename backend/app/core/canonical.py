"""
AgentSentinel v1.0: Canonical Security Request and Decision Models.
Establishes the unified internal request and decision representations
across REST APIs, Developer SDK, and Ecosystem Framework Adapters.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def generate_id(prefix: str = "req") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class CanonicalVerdict(str, Enum):
    """Canonical security decision verdicts."""
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    ERROR = "ERROR"


class CanonicalActionType(str, Enum):
    """Canonical action classifications."""
    READ = "READ"
    WRITE = "WRITE"
    EXECUTE = "EXECUTE"
    NETWORK = "NETWORK"
    DATA_ACCESS = "DATA_ACCESS"
    DELEGATE = "DELEGATE"
    MESSAGE = "MESSAGE"


class CanonicalSecurityRequest(BaseModel):
    """
    Unified canonical security request representation.
    All ingress vectors (REST, SDK, Framework Adapters, Multi-Agent Gateway)
    normalize into this model before pipeline evaluation.
    """
    request_id: str = Field(default_factory=lambda: generate_id("req"), description="Unique request identifier")
    correlation_id: str = Field(default_factory=lambda: generate_id("corr"), description="End-to-end distributed correlation ID")
    session_id: str = Field(..., description="Active session or trace context")
    agent_id: str = Field(..., description="Identity of executing AI agent")
    namespace: str = Field("default", description="Durable tenant / security namespace boundary")
    tool_name: str = Field(..., description="Name of tool or capability requested")
    action_type: str = Field("EXECUTE", description="Action classification (READ, WRITE, EXECUTE, NETWORK, DATA_ACCESS, etc.)")
    capability: str = Field("DEFAULT", description="Required agent capability tier")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Tool invocation parameters")
    target_resource: Optional[str] = Field("", description="Target URL, path, or resource identifier")
    user_id: str = Field("default_user", description="Human user or principal on whose behalf agent acts")
    role: str = Field("default_agent", description="Security role assigned to agent")
    task_summary: str = Field("", description="High-level task summary or prompt objective")
    prompt_context_summary: str = Field("", description="Summarized context window")
    delegation_id: Optional[str] = Field(None, description="Active delegation token ID if acting under delegation")
    framework_name: str = Field("REST", description="Originating framework (REST, SDK, LangChain, LangGraph, AutoGen, CrewAI, SemanticKernel)")
    framework_version: Optional[str] = Field(None, description="Framework software version")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Extensible contextual metadata")
    timestamp: datetime = Field(default_factory=utc_now, description="UTC ingestion timestamp")


class CanonicalSecurityDecision(BaseModel):
    """
    Unified canonical security decision representation.
    Synthesizes static policy, behavioral anomaly, and multi-agent governance verdicts
    into a standardized, explainable response.
    """
    verdict: CanonicalVerdict = Field(..., description="Final security verdict: ALLOW, DENY, REQUIRE_APPROVAL, ERROR")
    decision_reason: str = Field(..., description="Detailed, explainable justification for verdict")
    policy_name: Optional[str] = Field(None, description="Name of matched policy rule")
    matched_rule_id: Optional[str] = Field(None, description="Identifier of triggering policy rule")
    risk_score: float = Field(0.0, ge=0.0, le=1.0, description="Composite behavioral risk score (0.0 to 1.0)")
    anomaly_level: str = Field("NORMAL", description="Behavioral anomaly tier (NORMAL, ELEVATED, HIGH, CRITICAL)")
    approval_required: bool = Field(False, description="True if human approval must be obtained prior to execution")
    execution_allowed: bool = Field(False, description="True if physical execution is authorized")
    threat_flags: List[str] = Field(default_factory=list, description="MITRE ATLAS / OWASP threat indicator tags")
    policy_tags: List[str] = Field(default_factory=list, description="Applied security policy tags")
    risk_indicators: List[Any] = Field(default_factory=list, description="Specific risk factors detected")
    execution_restrictions: Dict[str, Any] = Field(default_factory=dict, description="Sandbox/guard restrictions")
    provenance_chain: List[str] = Field(default_factory=list, description="Multi-agent provenance history")
    namespace: str = Field("default", description="Namespace security boundary")
    event_id: str = Field(..., description="Durable audit event identifier in PostgreSQL")
    trace_id: str = Field(..., description="OpenTelemetry / audit trace identifier")
    request_id: str = Field(..., description="Correlated request identifier")
    correlation_id: str = Field(..., description="Distributed correlation ID")
    latency_ms: float = Field(0.0, description="Total interception and security evaluation latency in milliseconds")
    timestamp: datetime = Field(default_factory=utc_now, description="UTC verdict issuance timestamp")

    @property
    def allowed(self) -> bool:
        return self.execution_allowed and self.verdict == CanonicalVerdict.ALLOW

    @property
    def blocked(self) -> bool:
        return self.verdict == CanonicalVerdict.DENY or not self.execution_allowed


# --- Canonical Conversion Utilities ---

def from_tool_call_request(req: Any) -> CanonicalSecurityRequest:
    """Normalizes an app.interceptor.schema.ToolCallRequest into CanonicalSecurityRequest."""
    return CanonicalSecurityRequest(
        session_id=req.session_id,
        agent_id=req.agent_id,
        user_id=getattr(req, "user_id", "default_user"),
        tool_name=req.tool_name,
        arguments=req.arguments or {},
        action_type=getattr(req, "action_type", "EXECUTE"),
        capability=getattr(req, "capability", "DEFAULT"),
        role=getattr(req, "role", "default_agent"),
        task_summary=getattr(req, "task_summary", "") or "",
        prompt_context_summary=getattr(req, "prompt_context_summary", "") or "",
        target_resource=getattr(req, "target_resource", "") or "",
        delegation_id=getattr(req, "delegation_id", None),
        namespace=getattr(req, "namespace", "default") or "default",
        framework_name="REST",
        metadata={},
    )


def canonical_decision_to_interceptor_response(decision: CanonicalSecurityDecision, stored: bool = True) -> Any:
    """Translates CanonicalSecurityDecision into legacy InterceptorResponse for backwards compatibility."""
    from app.interceptor.schema import InterceptorResponse
    verdict_str = decision.verdict.value
    decision_str = "BLOCK" if verdict_str in ("DENY", "ERROR") else verdict_str
    ts = decision.timestamp
    ts_str = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)
    return InterceptorResponse(
        event_id=decision.event_id,
        decision=decision_str,
        decision_reason=decision.decision_reason,
        approval_required=decision.approval_required,
        execution_allowed=decision.execution_allowed,
        latency_ms=decision.latency_ms,
        stored=stored,
        trace_id=decision.trace_id,
        timestamp=ts_str,
    )


def canonical_decision_to_adapter_result(decision: CanonicalSecurityDecision) -> Any:
    """Translates CanonicalSecurityDecision into app.adapters.base.CanonicalSecurityResult."""
    from app.adapters.base import CanonicalSecurityResult
    verdict_str = decision.verdict.value
    decision_str = "BLOCK" if verdict_str == "DENY" else verdict_str
    return CanonicalSecurityResult(
        allowed=decision.allowed,
        decision=decision_str,
        decision_reason=decision.decision_reason,
        event_id=decision.event_id,
        trace_id=decision.trace_id,
        approval_required=decision.approval_required,
        execution_allowed=decision.execution_allowed,
        latency_ms=decision.latency_ms,
        namespace=decision.namespace,
        threat_flags=decision.threat_flags,
    )
