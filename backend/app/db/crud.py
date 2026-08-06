from typing import List, Optional
from sqlalchemy.orm import Session
from app.db.models import ApprovalModel, EventModel, ModelMetadataModel, PolicyModel, SessionModel
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
    """Retrieves existing session or creates a new session record."""
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
        db.add(db_session)
        db.commit()
        db.refresh(db_session)
    return db_session

# --- Event CRUD ---

def save_security_event(db: Session, security_event: SecurityEvent) -> EventModel:
    """Persists a Phase 3A SecurityEvent model into the database."""
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

    db.add(db_event)
    db.commit()
    db.refresh(db_event)
    return db_event

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
    """Creates a new security policy rule."""
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
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return policy

def list_active_policies(db: Session) -> List[PolicyModel]:
    """Retrieves all active security policies ordered by priority."""
    return db.query(PolicyModel).filter(PolicyModel.is_active == True).order_by(PolicyModel.priority.asc()).all()
