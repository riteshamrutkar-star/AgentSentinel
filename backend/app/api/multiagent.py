"""
Multi-Agent Governance & Security REST API Endpoints for AgentSentinel Phase 0.4.
Provides agent directory, capability registration, trust evaluation, message mediation,
delegation lifecycle management, and end-to-end action provenance.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db.crud import list_security_events
from app.db.session import get_db
from app.auth.models import AdminRole, AuthenticatedIdentity
from app.auth.dependencies import get_current_identity, require_role, require_namespace_access
from app.multiagent.config import multiagent_config
from app.multiagent.delegation import default_delegation_manager
from app.multiagent.interceptor import default_message_interceptor
from app.multiagent.models import (
    AgentCapability,
    AgentIdentity,
    AgentMessage,
    AgentStatus,
    AgentTrustResult,
    DelegationContext,
    DelegationDecision,
    MessageType,
    TrustLevel,
    utc_now,
)
from app.multiagent.registry import default_agent_registry
from app.multiagent.trust import default_trust_engine

router = APIRouter(prefix="/api/v1", tags=["Multi-Agent Governance"])


class AgentRegistrationRequest(BaseModel):
    """Payload for registering a new AI agent in AgentSentinel."""
    agent_id: str = Field(..., description="Unique agent identifier")
    name: str = Field(..., description="Human-readable agent display name")
    role: str = Field("default_agent", description="Security role")
    agent_type: str = Field("assistant", description="Agent architecture/type")
    owner: str = Field("system", description="Owner or launching principal")
    capabilities: List[str] = Field(default_factory=list, description="Authorized capabilities (e.g. SEARCH, FILE_READ)")
    trust_level: str = Field("STANDARD", description="UNTRUSTED, LIMITED, STANDARD, TRUSTED, PRIVILEGED")
    namespace: str = Field("default", description="Namespace security boundary")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Agent metadata")


class DelegationIssueRequest(BaseModel):
    """Direct request to issue a verified delegation token."""
    source_agent_id: str = Field(..., description="Delegating agent ID")
    target_agent_id: str = Field(..., description="Delegated agent ID")
    session_id: str = Field(..., description="Session identifier")
    action_name: str = Field(..., description="Task or action description")
    capabilities: List[str] = Field(..., description="Capabilities to delegate")
    provenance: Optional[List[str]] = Field(None, description="Current delegation provenance chain")
    namespace: str = Field("default", description="Namespace security boundary")


class InterceptMessageRequest(BaseModel):
    """Payload for submitting an agent-to-agent message for security mediation."""
    sender_agent_id: str = Field(..., description="Sending agent ID")
    recipient_agent_id: str = Field(..., description="Receiving agent ID")
    session_id: str = Field(..., description="Active session ID")
    requested_action: str = Field(..., description="Action requested")
    requested_capabilities: List[str] = Field(..., description="Capabilities required for action")
    parent_message_id: Optional[str] = Field(None, description="Parent message in chain")
    payload_metadata: Dict[str, Any] = Field(default_factory=dict, description="Sanitized metadata")
    provenance: Optional[List[str]] = Field(None, description="Provenance chain")
    namespace: str = Field("default", description="Namespace security boundary")


# --- Agent Identity Endpoints ---

@router.get("/agents", response_model=List[AgentIdentity], summary="List Registered Agents")
async def list_registered_agents(
    status_filter: Optional[str] = None,
    namespace: Optional[str] = None,
    identity: AuthenticatedIdentity = Depends(require_role(AdminRole.VIEWER)),
    db: Session = Depends(get_db)
):
    """Returns all agents registered in the AgentSentinel directory."""
    if namespace and not identity.can_access_namespace(namespace):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Unauthorized namespace access: Identity cannot access '{namespace}'.",
        )
    agents = default_agent_registry.list_agents(db, namespace=namespace)
    if status_filter:
        agents = [a for a in agents if a.status.value.upper() == status_filter.upper()]
    return agents


@router.post("/agents", response_model=AgentIdentity, status_code=status.HTTP_201_CREATED, summary="Register Agent")
async def register_new_agent(
    payload: AgentRegistrationRequest,
    identity: AuthenticatedIdentity = Depends(require_role(AdminRole.SECURITY_ADMIN)),
    db: Session = Depends(get_db)
):
    """Registers a new agent with explicit role, capabilities, and trust tier."""
    if not identity.can_access_namespace(payload.namespace):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Unauthorized namespace access: Identity cannot register agent in '{payload.namespace}'.",
        )
    # Convert capability strings
    caps: List[AgentCapability] = []
    for c in payload.capabilities:
        try:
            caps.append(AgentCapability(c.upper()))
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid capability '{c}'. Allowed: {[ac.value for ac in AgentCapability]}",
            )

    # Convert trust tier
    try:
        trust_tier = TrustLevel(payload.trust_level.upper())
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid trust level '{payload.trust_level}'. Allowed: {[tl.value for tl in TrustLevel]}",
        )

    score = multiagent_config.DEFAULT_TRUST_SCORES.get(trust_tier, 0.60)

    agent = AgentIdentity(
        agent_id=payload.agent_id,
        name=payload.name,
        role=payload.role,
        agent_type=payload.agent_type,
        owner=payload.owner,
        capabilities=caps,
        trust_level=trust_tier,
        trust_score=score,
        status=AgentStatus.ACTIVE,
        namespace=payload.namespace,
        created_at=utc_now(),
        metadata=payload.metadata,
    )

    return default_agent_registry.register_agent(agent, db)


@router.get("/agents/{agent_id}", response_model=AgentIdentity, summary="Get Agent Details")
async def get_agent_details(
    agent_id: str,
    identity: AuthenticatedIdentity = Depends(require_role(AdminRole.VIEWER)),
    db: Session = Depends(get_db)
):
    """Retrieves identity, capabilities, and status for a specific agent."""
    agent = default_agent_registry.get_agent(agent_id, db)
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_id}' not found in registry.",
        )
    if hasattr(agent, "namespace") and agent.namespace and not identity.can_access_namespace(agent.namespace):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Unauthorized namespace access: Identity cannot access agent in '{agent.namespace}'.",
        )
    return agent


@router.post("/agents/{agent_id}/revoke", summary="Revoke Agent Identity")
async def revoke_agent_identity(
    agent_id: str,
    identity: AuthenticatedIdentity = Depends(require_role(AdminRole.SECURITY_ADMIN)),
    db: Session = Depends(get_db)
):
    """Revokes an agent identity immediately. Terminating its ability to delegate or invoke tools."""
    success = default_agent_registry.revoke_agent(agent_id, db)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_id}' not found in registry.",
        )
    return {
        "status": "REVOKED",
        "agent_id": agent_id,
        "message": f"Agent '{agent_id}' has been successfully revoked and privileges disabled.",
    }


@router.get("/agents/{agent_id}/trust", response_model=AgentTrustResult, summary="Evaluate Agent Trust")
async def evaluate_agent_trust(
    agent_id: str,
    db: Session = Depends(get_db)
):
    """Calculates real-time explainable trust score and tier for an agent."""
    agent = default_agent_registry.get_agent(agent_id, db)
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_id}' not found in registry.",
        )
    return default_trust_engine.evaluate_agent_trust(agent_id, db)


# --- Agent-to-Agent Communication & Delegation Endpoints ---

@router.post("/agents/messages/intercept", response_model=DelegationDecision, summary="Intercept Agent Message")
async def intercept_agent_message(
    payload: InterceptMessageRequest,
    db: Session = Depends(get_db)
):
    """
    Submits an agent-to-agent message for security evaluation.
    Verifies identities, checks for privilege escalation, bounds delegation depth,
    and issues an active delegation context if authorized.
    """
    import uuid

    caps: List[AgentCapability] = []
    for c in payload.requested_capabilities:
        try:
            caps.append(AgentCapability(c.upper()))
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid capability '{c}'. Allowed: {[ac.value for ac in AgentCapability]}",
            )

    msg = AgentMessage(
        message_id=f"msg_{uuid.uuid4().hex[:8]}",
        sender_agent_id=payload.sender_agent_id,
        recipient_agent_id=payload.recipient_agent_id,
        session_id=payload.session_id,
        namespace=payload.namespace,
        parent_message_id=payload.parent_message_id,
        timestamp=utc_now(),
        message_type=MessageType.DELEGATION_REQUEST,
        requested_action=payload.requested_action,
        requested_capabilities=caps,
        payload_metadata=payload.payload_metadata,
        provenance=payload.provenance or [payload.sender_agent_id],
    )

    return default_message_interceptor.intercept_message(message=msg, db=db)


@router.post("/delegation/request", response_model=DelegationDecision, summary="Request Task Delegation")
async def request_task_delegation(
    payload: DelegationIssueRequest,
    db: Session = Depends(get_db)
):
    """
    Evaluates and issues an explicit task delegation from one agent to another.
    Enforces capability bounds and fail-closed security.
    """
    import uuid

    caps: List[AgentCapability] = []
    for c in payload.capabilities:
        try:
            caps.append(AgentCapability(c.upper()))
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid capability '{c}'. Allowed: {[ac.value for ac in AgentCapability]}",
            )

    msg = AgentMessage(
        message_id=f"del_req_{uuid.uuid4().hex[:8]}",
        sender_agent_id=payload.source_agent_id,
        recipient_agent_id=payload.target_agent_id,
        session_id=payload.session_id,
        namespace=payload.namespace,
        timestamp=utc_now(),
        message_type=MessageType.DELEGATION_REQUEST,
        requested_action=payload.action_name,
        requested_capabilities=caps,
        payload_metadata={"source": "api_request"},
        provenance=payload.provenance or [payload.source_agent_id],
    )

    return default_message_interceptor.intercept_message(message=msg, db=db)


@router.get("/delegation/{delegation_id}", response_model=DelegationContext, summary="Get Delegation Context")
async def get_delegation_context(
    delegation_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves verified delegation context details by delegation ID."""
    delegation = default_delegation_manager.get_delegation(delegation_id, db)
    if not delegation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Delegation token '{delegation_id}' not found.",
        )
    return delegation


@router.post("/delegation/{delegation_id}/revoke", summary="Revoke Delegation Context")
async def revoke_delegation_token(
    delegation_id: str,
    db: Session = Depends(get_db)
):
    """Revokes an active delegation token immediately, disabling downstream tool execution."""
    success = default_delegation_manager.revoke_delegation(delegation_id, db)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Delegation token '{delegation_id}' not found.",
        )
    return {
        "status": "REVOKED",
        "delegation_id": delegation_id,
        "message": f"Delegation token '{delegation_id}' has been revoked.",
    }


@router.get("/agents/{agent_id}/provenance", summary="Get Agent Provenance History")
async def get_agent_provenance(
    agent_id: str,
    db: Session = Depends(get_db)
):
    """Reconstructs historical delegation chains and provenance for an agent."""
    delegations = default_delegation_manager.list_delegations(db=db)
    agent_delegations = [
        d for d in delegations
        if d.source_agent_id == agent_id or d.target_agent_id == agent_id or agent_id in d.provenance_chain
    ]

    events = list_security_events(db, limit=50)
    provenance_events = []
    for evt in events:
        meta = getattr(evt, "metadata_json", {}) or {}
        ma = meta.get("multi_agent", {})
        if ma.get("source_agent_id") == agent_id or ma.get("target_agent_id") == agent_id or getattr(evt, "agent_id", "") == agent_id:
            provenance_events.append({
                "event_id": evt.event_id,
                "session_id": evt.session_id,
                "agent_id": evt.agent_id,
                "tool_name": evt.tool_name,
                "decision": evt.decision_result,
                "delegation_id": ma.get("delegation_id"),
                "provenance_chain": ma.get("provenance_chain", []),
                "timestamp": str(evt.timestamp),
            })

    return {
        "agent_id": agent_id,
        "total_delegations_involved": len(agent_delegations),
        "delegations": [d.model_dump() for d in agent_delegations],
        "audit_provenance_events": provenance_events,
    }
