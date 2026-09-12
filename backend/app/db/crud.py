import json
from typing import Any, List, Optional
from datetime import datetime
from sqlalchemy.orm import Session
from app.core.logger import logger
from app.db.models import (
    AgentModel,
    ApprovalModel,
    AttackRunModel,
    AttackScenarioModel,
    DelegationModel,
    EventModel,
    ExecutionModel,
    ModelMetadataModel,
    PolicyModel,
    ResearchDatasetModel,
    ResearchExperimentModel,
    ResearchObservationModel,
    ResearchRunModel,
    SecurityFindingModel,
    SessionModel,
)
from app.events.model import SecurityEvent

# --- Session CRUD ---

def get_or_create_session(
    db: Optional[Session],
    session_id: str,
    agent_id: str,
    user_id: str,
    role: str = "default_agent",
    framework_name: str = "LangChain",
) -> Optional[SessionModel]:
    """Retrieves existing session or creates a new session record with rollback protection."""
    if db is None:
        return None
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

def save_security_event(db: Optional[Session], security_event: SecurityEvent) -> Optional[EventModel]:
    """Persists a Phase 3A SecurityEvent model into PostgreSQL with transaction rollback safety."""
    if db is None:
        return None
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
    db: Optional[Session],
    session_id: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
) -> List[EventModel]:
    """Lists security events with optional session filtering."""
    if not db:
        return []
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


# --- Execution Audit CRUD ---

def create_execution_record(
    db: Session,
    execution_id: str,
    session_id: str,
    agent_id: str,
    tool_name: str,
    status: str = "COMPLETED",
    execution_backend: str = "IN_PROCESS_GUARDED",
    sandbox_profile: str = "STANDARD",
    execution_time_ms: float = 0.0,
    exit_code: int = 0,
    redacted: bool = False,
    detected_secrets: Optional[List[str]] = None,
    error_message: Optional[str] = None,
    sanitized_output_preview: Optional[str] = None,
) -> ExecutionModel:
    """Records a secure tool execution attempt with runtime metrics and redactions."""
    record = ExecutionModel(
        execution_id=execution_id,
        session_id=session_id,
        agent_id=agent_id,
        tool_name=tool_name,
        status=status,
        execution_backend=execution_backend,
        sandbox_profile=sandbox_profile,
        execution_time_ms=execution_time_ms,
        exit_code=exit_code,
        redacted=redacted,
        detected_secrets_json=detected_secrets or [],
        error_message=error_message,
        sanitized_output_preview=sanitized_output_preview,
    )
    try:
        db.add(record)
        db.commit()
        db.refresh(record)
        return record
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to record execution '{execution_id}': {e}", exc_info=True)
        raise


def get_execution_by_id(db: Session, execution_id: str) -> Optional[ExecutionModel]:
    """Retrieves an execution audit record by execution_id."""
    return db.query(ExecutionModel).filter(ExecutionModel.execution_id == execution_id).first()


def list_executions(
    db: Session,
    session_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    tool_name: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
) -> List[ExecutionModel]:
    """Lists execution records with optional filtering."""
    query = db.query(ExecutionModel)
    if session_id:
        query = query.filter(ExecutionModel.session_id == session_id)
    if agent_id:
        query = query.filter(ExecutionModel.agent_id == agent_id)
    if tool_name:
        query = query.filter(ExecutionModel.tool_name == tool_name)
    if status:
        query = query.filter(ExecutionModel.status == status)
    return query.order_by(ExecutionModel.created_at.desc()).limit(limit).all()


# --- Attack Simulation & Threat Intelligence CRUD ---

def record_attack_scenario(
    db: Session,
    scenario_id: str,
    name: str,
    category: str,
    severity: str,
    objective: str,
    description: str = "",
    mitre_atlas_id: str = "UNMAPPED",
    owasp_llm_id: str = "UNMAPPED",
    expected_decision: str = "BLOCK",
    expected_detector: str = "",
    is_multi_step: bool = False,
    enabled: bool = True,
    metadata: Optional[dict] = None,
) -> AttackScenarioModel:
    """Inserts or updates an AttackScenario definition in PostgreSQL."""
    existing = db.query(AttackScenarioModel).filter(AttackScenarioModel.scenario_id == scenario_id).first()
    if existing:
        existing.name = name
        existing.category = category
        existing.severity = severity
        existing.objective = objective
        existing.description = description
        existing.mitre_atlas_id = mitre_atlas_id
        existing.owasp_llm_id = owasp_llm_id
        existing.expected_decision = expected_decision
        existing.expected_detector = expected_detector
        existing.is_multi_step = is_multi_step
        existing.enabled = enabled
        existing.metadata_json = metadata or {}
        record = existing
    else:
        record = AttackScenarioModel(
            scenario_id=scenario_id,
            name=name,
            category=category,
            severity=severity,
            objective=objective,
            description=description,
            mitre_atlas_id=mitre_atlas_id,
            owasp_llm_id=owasp_llm_id,
            expected_decision=expected_decision,
            expected_detector=expected_detector,
            is_multi_step=is_multi_step,
            enabled=enabled,
            metadata_json=metadata or {},
        )
        db.add(record)
    try:
        db.commit()
        db.refresh(record)
        return record
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to record attack scenario '{scenario_id}': {e}", exc_info=True)
        raise


def get_attack_scenario_by_id(db: Session, scenario_id: str) -> Optional[AttackScenarioModel]:
    """Retrieves an attack scenario by ID."""
    return db.query(AttackScenarioModel).filter(AttackScenarioModel.scenario_id == scenario_id).first()


def list_attack_scenarios(
    db: Session,
    category: Optional[str] = None,
    enabled: Optional[bool] = None,
    limit: int = 100,
) -> List[AttackScenarioModel]:
    """Lists attack scenarios with optional filtering."""
    query = db.query(AttackScenarioModel)
    if category:
        query = query.filter(AttackScenarioModel.category == category)
    if enabled is not None:
        query = query.filter(AttackScenarioModel.enabled == enabled)
    return query.order_by(AttackScenarioModel.scenario_id.asc()).limit(limit).all()


def record_attack_run(
    db: Session,
    run_id: str,
    scenario_id: str,
    category: str,
    baseline_type: str,
    status: str,
    interrupted_at_step: Optional[int],
    total_steps: int,
    prevention_stage: Optional[str],
    final_decision: str,
    actual_decision: str,
    is_successful_attack: bool,
    execution_time_ms: float,
    step_results: Optional[list] = None,
    graph_nodes: Optional[list] = None,
    graph_edges: Optional[list] = None,
    summary_notes: str = "",
) -> AttackRunModel:
    """Inserts a completed attack run audit record into PostgreSQL."""
    record = AttackRunModel(
        run_id=run_id,
        scenario_id=scenario_id,
        category=category,
        baseline_type=baseline_type,
        status=status,
        interrupted_at_step=interrupted_at_step,
        total_steps=total_steps,
        prevention_stage=prevention_stage,
        final_decision=final_decision,
        actual_decision=actual_decision,
        is_successful_attack=is_successful_attack,
        execution_time_ms=execution_time_ms,
        step_results_json=step_results or [],
        graph_nodes_json=graph_nodes or [],
        graph_edges_json=graph_edges or [],
        summary_notes=summary_notes,
    )
    try:
        db.add(record)
        db.commit()
        db.refresh(record)
        return record
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to record attack run '{run_id}': {e}", exc_info=True)
        raise


def get_attack_run_by_id(db: Session, run_id: str) -> Optional[AttackRunModel]:
    """Retrieves an attack run audit record by ID."""
    return db.query(AttackRunModel).filter(AttackRunModel.run_id == run_id).first()


def list_attack_runs(
    db: Session,
    scenario_id: Optional[str] = None,
    category: Optional[str] = None,
    baseline_type: Optional[str] = None,
    limit: int = 100,
) -> List[AttackRunModel]:
    """Lists attack run audit records with optional filtering."""
    query = db.query(AttackRunModel)
    if scenario_id:
        query = query.filter(AttackRunModel.scenario_id == scenario_id)
    if category:
        query = query.filter(AttackRunModel.category == category)
    if baseline_type:
        query = query.filter(AttackRunModel.baseline_type == baseline_type)
    return query.order_by(AttackRunModel.created_at.desc()).limit(limit).all()


def record_security_finding(
    db: Session,
    finding_id: str,
    run_id: str,
    scenario_id: str,
    category: str,
    severity: str,
    title: str,
    description: str = "",
    remediation: str = "",
    mitre_atlas_id: str = "UNMAPPED",
    owasp_llm_id: str = "UNMAPPED",
    prevented_by: str = "POLICY_ENGINE",
    evidence: Optional[list] = None,
) -> SecurityFindingModel:
    """Inserts a structured threat intelligence security finding into PostgreSQL."""
    record = SecurityFindingModel(
        finding_id=finding_id,
        run_id=run_id,
        scenario_id=scenario_id,
        category=category,
        severity=severity,
        title=title,
        description=description,
        remediation=remediation,
        mitre_atlas_id=mitre_atlas_id,
        owasp_llm_id=owasp_llm_id,
        prevented_by=prevented_by,
        evidence_json=evidence or [],
    )
    try:
        db.add(record)
        db.commit()
        db.refresh(record)
        return record
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to record security finding '{finding_id}': {e}", exc_info=True)
        raise


def list_security_findings(
    db: Session,
    run_id: Optional[str] = None,
    scenario_id: Optional[str] = None,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
) -> List[SecurityFindingModel]:
    """Lists security findings with optional filtering."""
    query = db.query(SecurityFindingModel)
    if run_id:
        query = query.filter(SecurityFindingModel.run_id == run_id)
    if scenario_id:
        query = query.filter(SecurityFindingModel.scenario_id == scenario_id)
    if category:
        query = query.filter(SecurityFindingModel.category == category)
    if severity:
        query = query.filter(SecurityFindingModel.severity == severity)
    return query.order_by(SecurityFindingModel.created_at.desc()).limit(limit).all()


def get_security_finding_by_id(db: Session, finding_id: str) -> Optional[SecurityFindingModel]:
    """Retrieves a security finding by ID."""
    return db.query(SecurityFindingModel).filter(SecurityFindingModel.finding_id == finding_id).first()


# =============================================================================
# Phase 0.7: Research Experiment, Run, Observation & Dataset CRUD
# =============================================================================

def _json_safe(obj: Any) -> Any:
    """Recursively serializes objects such as datetime into JSON-compatible primitives."""
    if obj is None:
        return {}
    if isinstance(obj, (dict, list)):
        return json.loads(json.dumps(obj, default=str))
    return obj


def record_research_experiment(
    db: Optional[Session],
    experiment_id: str,
    name: str,
    description: str = "",
    dataset_id: str = "dataset-v1.0",
    config: Optional[dict] = None,
    status: str = "COMPLETED",
) -> Optional[ResearchExperimentModel]:
    """Records a research study experiment in PostgreSQL."""
    if db is None:
        return None
    existing = db.query(ResearchExperimentModel).filter(ResearchExperimentModel.experiment_id == experiment_id).first()
    if existing:
        existing.status = status
        db.commit()
        return existing
    record = ResearchExperimentModel(
        experiment_id=experiment_id,
        name=name,
        description=description,
        dataset_id=dataset_id,
        config_json=_json_safe(config),
        status=status,
    )
    try:
        db.add(record)
        db.commit()
        db.refresh(record)
        return record
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to record research experiment '{experiment_id}': {e}", exc_info=True)
        return None


def get_research_experiment(db: Optional[Session], experiment_id: str) -> Optional[ResearchExperimentModel]:
    """Retrieves a research experiment by ID."""
    if db is None:
        return None
    return db.query(ResearchExperimentModel).filter(ResearchExperimentModel.experiment_id == experiment_id).first()


def list_research_experiments(db: Optional[Session], limit: int = 50) -> List[ResearchExperimentModel]:
    """Lists research experiments ordered by creation timestamp."""
    if db is None:
        return []
    return db.query(ResearchExperimentModel).order_by(ResearchExperimentModel.created_at.desc()).limit(limit).all()


def record_research_run(
    db: Optional[Session],
    run_id: str,
    experiment_id: str,
    variant: str,
    seed: int = 42,
    total_scenarios: int = 0,
    total_observations: int = 0,
    f1_score: float = 0.0,
    precision: float = 0.0,
    recall: float = 0.0,
    detection_rate: float = 0.0,
    fpr: float = 0.0,
    latency_median_ms: float = 0.0,
    execution_time_ms: float = 0.0,
    metrics_summary: Optional[dict] = None,
    manifest: Optional[dict] = None,
) -> Optional[ResearchRunModel]:
    """Records an empirical research run trial in PostgreSQL."""
    if db is None:
        return None
    record = ResearchRunModel(
        run_id=run_id,
        experiment_id=experiment_id,
        variant=variant,
        seed=seed,
        total_scenarios=total_scenarios,
        total_observations=total_observations,
        f1_score=f1_score,
        precision=precision,
        recall=recall,
        detection_rate=detection_rate,
        fpr=fpr,
        latency_median_ms=latency_median_ms,
        execution_time_ms=execution_time_ms,
        metrics_summary_json=_json_safe(metrics_summary),
        manifest_json=_json_safe(manifest),
    )
    try:
        db.add(record)
        db.commit()
        db.refresh(record)
        return record
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to record research run '{run_id}': {e}", exc_info=True)
        return None


def get_research_run(db: Optional[Session], run_id: str) -> Optional[ResearchRunModel]:
    """Retrieves a research run by ID."""
    if db is None:
        return None
    return db.query(ResearchRunModel).filter(ResearchRunModel.run_id == run_id).first()


def list_research_runs(
    db: Optional[Session], experiment_id: Optional[str] = None, limit: int = 100
) -> List[ResearchRunModel]:
    """Lists research runs with optional filtering by experiment_id."""
    if db is None:
        return []
    query = db.query(ResearchRunModel)
    if experiment_id:
        query = query.filter(ResearchRunModel.experiment_id == experiment_id)
    return query.order_by(ResearchRunModel.created_at.desc()).limit(limit).all()


def record_research_observation(
    db: Optional[Session],
    observation_id: str,
    experiment_id: str,
    run_id: str,
    scenario_id: str,
    variant: str,
    expected_outcome: str,
    actual_outcome: str,
    attribution: str = "MISSED",
    latency_ms: float = 0.0,
    passed: bool = True,
) -> Optional[ResearchObservationModel]:
    """Records an unaggregated scenario observation trial."""
    if db is None:
        return None
    record = ResearchObservationModel(
        observation_id=observation_id,
        experiment_id=experiment_id,
        run_id=run_id,
        scenario_id=scenario_id,
        variant=variant,
        expected_outcome=expected_outcome,
        actual_outcome=actual_outcome,
        attribution=attribution,
        latency_ms=latency_ms,
        passed=passed,
    )
    try:
        db.add(record)
        db.commit()
        db.refresh(record)
        return record
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to record research observation '{observation_id}': {e}", exc_info=True)
        return None


def list_research_observations(
    db: Optional[Session],
    experiment_id: Optional[str] = None,
    run_id: Optional[str] = None,
    limit: int = 1000,
) -> List[ResearchObservationModel]:
    """Lists raw scenario observations."""
    if db is None:
        return []
    query = db.query(ResearchObservationModel)
    if experiment_id:
        query = query.filter(ResearchObservationModel.experiment_id == experiment_id)
    if run_id:
        query = query.filter(ResearchObservationModel.run_id == run_id)
    return query.order_by(ResearchObservationModel.created_at.asc()).limit(limit).all()


def record_research_dataset(
    db: Optional[Session],
    dataset_id: str,
    version: str,
    description: str,
    total_scenarios: int,
    sha256_hash: str,
) -> Optional[ResearchDatasetModel]:
    """Registers or updates benchmark dataset metadata."""
    if db is None:
        return None
    existing = db.query(ResearchDatasetModel).filter(ResearchDatasetModel.dataset_id == dataset_id).first()
    if existing:
        existing.version = version
        existing.description = description
        existing.total_scenarios = total_scenarios
        existing.sha256_hash = sha256_hash
        db.commit()
        return existing
    record = ResearchDatasetModel(
        dataset_id=dataset_id,
        version=version,
        description=description,
        total_scenarios=total_scenarios,
        sha256_hash=sha256_hash,
    )
    try:
        db.add(record)
        db.commit()
        db.refresh(record)
        return record
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to record research dataset '{dataset_id}': {e}", exc_info=True)
        return None


def get_research_dataset(db: Optional[Session], dataset_id: str) -> Optional[ResearchDatasetModel]:
    """Retrieves dataset metadata by ID."""
    if db is None:
        return None
    return db.query(ResearchDatasetModel).filter(ResearchDatasetModel.dataset_id == dataset_id).first()



