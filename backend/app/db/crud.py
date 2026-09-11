from typing import List, Optional
from datetime import datetime
from sqlalchemy.orm import Session
from app.core.logger import logger
from app.db.models import (
    AgentModel,
    ApprovalModel,
    DelegationModel,
    EventModel,
    ModelMetadataModel,
    PolicyModel,
    SessionModel,
)
from app.events.model import SecurityEvent

# --- Session CRUD ---

def get_or_create_session(
    db: Session,
    session_id: str,
    agent_id: str,
    user_id: str,
    role: str = "default_agent",
    framework_name: str = "LangChain",
) -> SessionModel:
    """Retrieves existing session or creates a new session record with rollback protection."""
    db_session = db.query(SessionModel).filter(SessionModel.session_id == session_id).first()
    if not db_session:
        db_session = SessionModel(
            session_id=session_id,
            agent_id=agent_id,
            user_id=user_id,
            role=role,
            framework_name=framework_name,
            status="ACTIVE",
        )
        try:
            db.add(db_session)
            db.commit()
            db.refresh(db_session)
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to create session record '{session_id}': {e}", exc_info=True)
            raise
    return db_session

# --- Event CRUD ---

def save_security_event(db: Session, security_event: SecurityEvent) -> EventModel:
    """Persists a Phase 3A SecurityEvent model into PostgreSQL with transaction rollback safety."""
    # Ensure parent session exists
    get_or_create_session(
        db=db,
        session_id=security_event.identity.session_id,
        agent_id=security_event.identity.agent_id,
        user_id=security_event.identity.user_id,
        role=security_event.identity.role,
        framework_name=security_event.identity.framework_name,
    )

    schema_dict = security_event.to_dict()

    db_event = EventModel(
        event_id=security_event.identity.event_id,
        session_id=security_event.identity.session_id,
        agent_id=security_event.identity.agent_id,
        user_id=security_event.identity.user_id,
        role=security_event.identity.role,
        framework_name=security_event.identity.framework_name,

        task_summary=security_event.task_context.task_summary,
        prompt_context_summary=security_event.task_context.prompt_context_summary,
        session_state=security_event.task_context.session_state,
        previous_action_count=security_event.task_context.previous_action_count,
        recent_tool_history_json=security_event.task_context.recent_tool_history,

        tool_name=security_event.tool_action.tool_name,
        action_type=security_event.tool_action.action_type.value if hasattr(security_event.tool_action.action_type, 'value') else security_event.tool_action.action_type,
        target_resource=security_event.tool_action.target_resource,
        arguments_payload_json=security_event.tool_action.arguments_payload,
        source_module=security_event.tool_action.source_module,
        execution_stage=security_event.tool_action.execution_stage.value if hasattr(security_event.tool_action.execution_stage, 'value') else security_event.tool_action.execution_stage,

        permission_level=security_event.security_context.permission_level,
        policy_tags_json=security_event.security_context.policy_tags,
        sensitivity_level=security_event.security_context.sensitivity_level.value if hasattr(security_event.security_context.sensitivity_level, 'value') else security_event.security_context.sensitivity_level,
        risk_indicators_json=security_event.security_context.risk_indicators,
        anomaly_score=security_event.security_context.anomaly_score,
        threat_flags_json=security_event.security_context.threat_flags,

        policy_result=security_event.decision_context.policy_result.value if hasattr(security_event.decision_context.policy_result, 'value') else security_event.decision_context.policy_result,
        decision_result=security_event.decision_context.decision_result,
        decision_reason=security_event.decision_context.decision_reason,
        approval_required=security_event.decision_context.approval_required,
        reviewer=security_event.decision_context.reviewer,
        approval_status=security_event.decision_context.approval_status.value if hasattr(security_event.decision_context.approval_status, 'value') else security_event.decision_context.approval_status,

        execution_allowed=security_event.execution_context.execution_allowed,
        execution_result_json=security_event.execution_context.execution_result,
        latency_ms=security_event.execution_context.latency_ms,
        error_message=security_event.execution_context.error_message,
        retry_count=security_event.execution_context.retry_count,

        log_status=security_event.audit_context.log_status,
        is_stored=True,
        trace_id=security_event.audit_context.trace_id,
        correlation_id=security_event.audit_context.correlation_id,
        metadata_json=security_event.audit_context.metadata,

        raw_payload_json=schema_dict,
    )

    try:
        db.add(db_event)
        db.commit()
        db.refresh(db_event)
        return db_event
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to save security event '{security_event.identity.event_id}': {e}", exc_info=True)
        raise

def get_security_event_by_id(db: Session, event_id: str) -> Optional[EventModel]:
    """Retrieves a single security event record by event_id."""
    return db.query(EventModel).filter(EventModel.event_id == event_id).first()

def list_security_events(
    db: Session,
    session_id: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
) -> List[EventModel]:
    """Lists security events with optional session filtering."""
    query = db.query(EventModel)
    if session_id:
        query = query.filter(EventModel.session_id == session_id)
    return query.order_by(EventModel.timestamp.desc()).offset(offset).limit(limit).all()

# --- Policy CRUD ---

def create_policy(
    db: Session,
    policy_name: str,
    effect: str,
    role: str = "*",
    tool_name: str = "*",
    action_type: str = "*",
    resource_pattern: str = "*",
    description: str = "",
    priority: int = 100,
) -> PolicyModel:
    """Creates a new security policy rule with transaction rollback safety."""
    policy = PolicyModel(
        policy_name=policy_name,
        effect=effect,
        role=role,
        tool_name=tool_name,
        action_type=action_type,
        resource_pattern=resource_pattern,
        description=description,
        priority=priority,
        is_active=True,
    )
    try:
        db.add(policy)
        db.commit()
        db.refresh(policy)
        return policy
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to create policy '{policy_name}': {e}", exc_info=True)
        raise

def list_active_policies(db: Session) -> List[PolicyModel]:
    """Retrieves all active security policies ordered by priority."""
    return db.query(PolicyModel).filter(PolicyModel.is_active == True).order_by(PolicyModel.priority.asc()).all()


# --- Multi-Agent Identity & Delegation CRUD ---

def register_or_update_agent(
    db: Session,
    agent_id: str,
    name: str,
    role: str = "default_agent",
    agent_type: str = "assistant",
    owner: str = "system",
    capabilities: Optional[List[str]] = None,
    trust_level: str = "STANDARD",
    trust_score: float = 0.60,
    status: str = "ACTIVE",
    metadata: Optional[dict] = None,
) -> AgentModel:
    """Registers a new agent or updates an existing agent identity record."""
    agent = db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()
    caps = capabilities if capabilities is not None else []
    meta = metadata if metadata is not None else {}

    if not agent:
        agent = AgentModel(
            agent_id=agent_id,
            name=name,
            role=role,
            agent_type=agent_type,
            owner=owner,
            capabilities_json=caps,
            trust_level=trust_level,
            trust_score=trust_score,
            status=status,
            metadata_json=meta,
        )
        db.add(agent)
    else:
        agent.name = name
        agent.role = role
        agent.agent_type = agent_type
        agent.owner = owner
        agent.capabilities_json = caps
        agent.trust_level = trust_level
        agent.trust_score = trust_score
        agent.status = status
        agent.metadata_json = meta

    try:
        db.commit()
        db.refresh(agent)
        return agent
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to register/update agent '{agent_id}': {e}", exc_info=True)
        raise


def get_agent_by_id(db: Session, agent_id: str) -> Optional[AgentModel]:
    """Retrieves an agent identity record by agent_id."""
    return db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()


def list_agents(db: Session, status: Optional[str] = None) -> List[AgentModel]:
    """Lists registered agents, optionally filtered by operational status."""
    query = db.query(AgentModel)
    if status:
        query = query.filter(AgentModel.status == status)
    return query.order_by(AgentModel.created_at.asc()).all()


def update_agent_status(db: Session, agent_id: str, status: str) -> Optional[AgentModel]:
    """Updates the lifecycle status of an agent (e.g. ACTIVE, REVOKED, SUSPENDED)."""
    agent = db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()
    if not agent:
        return None
    agent.status = status
    try:
        db.commit()
        db.refresh(agent)
        return agent
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to update status for agent '{agent_id}': {e}", exc_info=True)
        raise


def update_agent_trust(db: Session, agent_id: str, trust_score: float, trust_level: str) -> Optional[AgentModel]:
    """Updates the calculated trust score and level for an agent."""
    agent = db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()
    if not agent:
        return None
    agent.trust_score = trust_score
    agent.trust_level = trust_level
    try:
        db.commit()
        db.refresh(agent)
        return agent
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to update trust for agent '{agent_id}': {e}", exc_info=True)
        raise


def create_delegation(
    db: Session,
    delegation_id: str,
    source_agent_id: str,
    target_agent_id: str,
    session_id: str,
    delegated_capabilities: List[str],
    resource_scope: str = "*",
    delegation_depth: int = 1,
    parent_delegation_id: Optional[str] = None,
    expires_at: Optional[datetime] = None,
    provenance_chain: Optional[List[str]] = None,
    metadata: Optional[dict] = None,
) -> DelegationModel:
    """Persists a new delegation record in PostgreSQL."""
    chain = provenance_chain if provenance_chain is not None else [source_agent_id, target_agent_id]
    meta = metadata if metadata is not None else {}

    delegation = DelegationModel(
        delegation_id=delegation_id,
        source_agent_id=source_agent_id,
        target_agent_id=target_agent_id,
        session_id=session_id,
        parent_delegation_id=parent_delegation_id,
        delegated_capabilities_json=delegated_capabilities,
        resource_scope=resource_scope,
        delegation_depth=delegation_depth,
        status="ACTIVE",
        expires_at=expires_at,
        provenance_chain_json=chain,
        metadata_json=meta,
    )
    try:
        db.add(delegation)
        db.commit()
        db.refresh(delegation)
        return delegation
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to create delegation record '{delegation_id}': {e}", exc_info=True)
        raise


def get_delegation_by_id(db: Session, delegation_id: str) -> Optional[DelegationModel]:
    """Retrieves a delegation record by delegation_id."""
    return db.query(DelegationModel).filter(DelegationModel.delegation_id == delegation_id).first()


def list_delegations(
    db: Session,
    session_id: Optional[str] = None,
    status: Optional[str] = None
) -> List[DelegationModel]:
    """Lists delegation records with optional session and status filtering."""
    query = db.query(DelegationModel)
    if session_id:
        query = query.filter(DelegationModel.session_id == session_id)
    if status:
        query = query.filter(DelegationModel.status == status)
    return query.order_by(DelegationModel.created_at.desc()).all()


def revoke_delegation(db: Session, delegation_id: str) -> bool:
    """Revokes an active delegation context immediately."""
    delegation = db.query(DelegationModel).filter(DelegationModel.delegation_id == delegation_id).first()
    if not delegation:
        return False
    delegation.status = "REVOKED"
    try:
        db.commit()
        return True
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to revoke delegation '{delegation_id}': {e}", exc_info=True)
        raise

