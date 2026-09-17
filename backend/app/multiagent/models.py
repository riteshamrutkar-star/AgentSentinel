"""
Domain models and Pydantic schemas for Multi-Agent Security & Governance (Phase 0.4).
Defines agent identities, trust levels, capabilities, messages, delegations, and provenance.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class TrustLevel(str, Enum):
    """Explicit, centralized agent trust tiers."""
    UNTRUSTED = "UNTRUSTED"
    LIMITED = "LIMITED"
    STANDARD = "STANDARD"
    TRUSTED = "TRUSTED"
    PRIVILEGED = "PRIVILEGED"


class AgentStatus(str, Enum):
    """Operational status of an agent in the registry."""
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"


class AgentCapability(str, Enum):
    """Granular capabilities possessed or delegated by agents."""
    SEARCH = "SEARCH"
    FILE_READ = "FILE_READ"
    FILE_WRITE = "FILE_WRITE"
    NETWORK_ACCESS = "NETWORK_ACCESS"
    DATABASE_READ = "DATABASE_READ"
    DATABASE_WRITE = "DATABASE_WRITE"
    PROCESS_EXECUTION = "PROCESS_EXECUTION"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    DELEGATION = "DELEGATION"


class MessageType(str, Enum):
    """Types of agent-to-agent messages."""
    DELEGATION_REQUEST = "DELEGATION_REQUEST"
    TASK_RESULT = "TASK_RESULT"
    STATUS_QUERY = "STATUS_QUERY"
    INFORMATIONAL = "INFORMATIONAL"


class AgentIdentity(BaseModel):
    """Stable first-class identity for an autonomous AI agent."""
    agent_id: str = Field(..., description="Globally unique agent identifier")
    name: str = Field(..., description="Human-readable agent name")
    role: str = Field("default_agent", description="Security role (e.g., research_coordinator, research_worker)")
    agent_type: str = Field("assistant", description="Agent architecture/type (coordinator, worker, evaluator)")
    owner: str = Field("system", description="Owner, tenant, or launching principal")
    capabilities: List[AgentCapability] = Field(default_factory=list, description="Explicitly authorized capabilities")
    trust_level: TrustLevel = Field(TrustLevel.STANDARD, description="Assigned trust tier")
    trust_score: float = Field(0.60, ge=0.0, le=1.0, description="Normalized trust score (0.0 to 1.0)")
    status: AgentStatus = Field(AgentStatus.ACTIVE, description="Current lifecycle status")
    namespace: str = Field("default", description="Namespace security boundary")
    created_at: datetime = Field(default_factory=utc_now, description="UTC registration timestamp")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary non-sensitive agent metadata")


class AgentTrustResult(BaseModel):
    """Structured, explainable trust evaluation result for an agent."""
    agent_id: str = Field(..., description="Target agent evaluated")
    trust_score: float = Field(..., ge=0.0, le=1.0, description="Evaluated trust score")
    trust_level: TrustLevel = Field(..., description="Resulting trust level tier")
    factors: List[str] = Field(default_factory=list, description="Contributing positive or negative factors")
    explanation: str = Field(..., description="Human-readable explanation of trust score")
    confidence: float = Field(0.85, ge=0.0, le=1.0, description="Confidence in trust evaluation")


class AgentMessage(BaseModel):
    """Structured representation of an agent-to-agent communication or delegation request."""
    message_id: str = Field(..., description="Unique message UUID")
    sender_agent_id: str = Field(..., description="Initiating agent ID")
    recipient_agent_id: str = Field(..., description="Target agent ID")
    session_id: str = Field(..., description="Workflow session identifier")
    namespace: str = Field("default", description="Namespace security boundary")
    parent_message_id: Optional[str] = Field(None, description="Parent message in conversation/delegation tree")
    timestamp: datetime = Field(default_factory=utc_now, description="Message dispatch timestamp")
    message_type: MessageType = Field(MessageType.DELEGATION_REQUEST, description="Category of agent message")
    requested_action: str = Field(..., description="High-level action or task description")
    requested_capabilities: List[AgentCapability] = Field(default_factory=list, description="Capabilities requested for delegation")
    payload_metadata: Dict[str, Any] = Field(default_factory=dict, description="Sanitized metadata (no raw secrets)")
    provenance: List[str] = Field(default_factory=list, description="Ordered delegation chain of agent IDs")
    risk_context: Dict[str, Any] = Field(default_factory=dict, description="Pre-computed or situational risk markers")


class DelegationContext(BaseModel):
    """Secure, auditable representation of delegated authority between agents."""
    delegation_id: str = Field(..., description="Unique delegation token/context identifier")
    source_agent_id: str = Field(..., description="Delegating agent ID")
    target_agent_id: str = Field(..., description="Delegated agent ID")
    session_id: str = Field(..., description="Associated workflow session")
    namespace: str = Field("default", description="Namespace security boundary")
    parent_delegation_id: Optional[str] = Field(None, description="Parent delegation token if sub-delegated")
    delegated_capabilities: List[AgentCapability] = Field(..., description="Constrained capabilities granted to delegatee")
    resource_scope: str = Field("*", description="Target resource or path pattern restriction")
    delegation_depth: int = Field(1, ge=1, description="Depth level in delegation chain (1 = direct)")
    status: str = Field("ACTIVE", description="Delegation status (ACTIVE, REVOKED, EXPIRED)")
    expires_at: Optional[datetime] = Field(None, description="Optional TTL expiration timestamp")
    issued_at: datetime = Field(default_factory=utc_now, description="Issuance timestamp")
    provenance_chain: List[str] = Field(default_factory=list, description="Full agent delegation chain [A, B, ...]")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Delegation context metadata")


class DelegationDecision(BaseModel):
    """Structured security verdict for an agent delegation or message interception."""
    delegation_id: Optional[str] = Field(None, description="Issued delegation ID if allowed")
    decision: str = Field(..., description="ALLOW, BLOCK, or REQUIRE_APPROVAL")
    reason: str = Field(..., description="Human-readable decision explanation")
    escalation_detected: bool = Field(False, description="True if capability or privilege escalation was detected")
    escalation_details: Optional[str] = Field(None, description="Details of unauthorized escalation attempt")
    trust_score: float = Field(0.0, ge=0.0, le=1.0, description="Sender evaluated trust score")
    risk_score: float = Field(0.0, ge=0.0, le=1.0, description="Multi-agent composite risk score")
    execution_allowed: bool = Field(False, description="True if delegation is authorized to proceed")
    latency_ms: float = Field(0.0, description="Evaluation latency in milliseconds")
