import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import relationship
from app.db.base import Base

def utc_now():
    return datetime.now(timezone.utc)

class SessionModel(Base):
    """Stores agent session metadata."""
    __tablename__ = "sessions"

    session_id = Column(String(64), primary_key=True, index=True)
    agent_id = Column(String(64), nullable=False, index=True)
    user_id = Column(String(64), nullable=False, index=True)
    role = Column(String(64), default="default_agent")
    framework_name = Column(String(64), default="LangChain")
    started_at = Column(DateTime(timezone=True), default=utc_now)
    ended_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(String(32), default="ACTIVE")

    # Relationship to events
    events = relationship("EventModel", back_populates="session", cascade="all, delete-orphan")

class EventModel(Base):
    """Stores every intercepted security event with full Phase 3A attribute mapping."""
    __tablename__ = "security_events"

    event_id = Column(String(64), primary_key=True, index=True)
    session_id = Column(String(64), ForeignKey("sessions.session_id"), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), default=utc_now, index=True)

    # Identity Fields
    agent_id = Column(String(64), nullable=False, index=True)
    user_id = Column(String(64), nullable=False, index=True)
    role = Column(String(64), default="default_agent")
    framework_name = Column(String(64), default="LangChain")

    # Context Fields
    task_summary = Column(Text, default="")
    prompt_context_summary = Column(Text, default="")
    session_state = Column(String(32), default="ACTIVE")
    previous_action_count = Column(Integer, default=0)
    recent_tool_history_json = Column(JSON, default=list)

    # Tool Action Fields
    tool_name = Column(String(128), nullable=False, index=True)
    action_type = Column(String(32), default="UNKNOWN")
    target_resource = Column(Text, default="")
    arguments_payload_json = Column(JSON, default=dict)
    source_module = Column(String(128), default="agent.tools")
    execution_stage = Column(String(32), default="PRE_EXECUTION")

    # Security Context Fields
    permission_level = Column(String(64), default="USER")
    policy_tags_json = Column(JSON, default=list)
    sensitivity_level = Column(String(32), default="LOW")
    risk_indicators_json = Column(JSON, default=list)
    anomaly_score = Column(Float, default=0.0)
    threat_flags_json = Column(JSON, default=list)

    # Decision Context Fields
    policy_result = Column(String(32), default="ALLOW")
    decision_result = Column(String(32), default="ALLOW", index=True)
    decision_reason = Column(Text, default="")
    approval_required = Column(Boolean, default=False)
    reviewer = Column(String(64), nullable=True)
    approval_status = Column(String(32), default="NOT_REQUIRED", index=True)

    # Execution Context Fields
    execution_allowed = Column(Boolean, default=True, index=True)
    execution_result_json = Column(JSON, nullable=True)
    latency_ms = Column(Float, default=0.0)
    error_message = Column(Text, nullable=True)
    retry_count = Column(Integer, default=0)

    # Audit Context Fields
    log_status = Column(String(32), default="RECORDED")
    is_stored = Column(Boolean, default=True)
    trace_id = Column(String(64), default="")
    correlation_id = Column(String(64), default="")
    metadata_json = Column(JSON, default=dict)

    # Complete Raw JSON representation
    raw_payload_json = Column(JSON, nullable=False)

    created_at = Column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    # Relationships
    session = relationship("SessionModel", back_populates="events")
    approvals = relationship("ApprovalModel", back_populates="event", cascade="all, delete-orphan")

class PolicyModel(Base):
    """Stores security policies evaluated by the policy engine."""
    __tablename__ = "policies"

    policy_id = Column(String(64), primary_key=True, default=lambda: f"pol_{uuid.uuid4().hex[:8]}")
    policy_name = Column(String(128), nullable=False)
    description = Column(Text, default="")
    role = Column(String(64), default="*")
    tool_name = Column(String(128), default="*")
    action_type = Column(String(32), default="*")
    resource_pattern = Column(String(256), default="*")
    effect = Column(String(32), nullable=False, default="ALLOW")  # ALLOW, DENY, REQUIRE_APPROVAL
    priority = Column(Integer, default=100)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

class ApprovalModel(Base):
    """Stores review & approval records for sensitive actions."""
    __tablename__ = "approvals"

    approval_id = Column(String(64), primary_key=True, default=lambda: f"appr_{uuid.uuid4().hex[:8]}")
    event_id = Column(String(64), ForeignKey("security_events.event_id"), nullable=False, index=True)
    requested_at = Column(DateTime(timezone=True), default=utc_now)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    reviewer = Column(String(64), nullable=True)
    decision = Column(String(32), default="PENDING")
    notes = Column(Text, nullable=True)
    status = Column(String(32), default="PENDING", index=True)

    event = relationship("EventModel", back_populates="approvals")

class ModelMetadataModel(Base):
    """Stores anomaly detector model metadata and configuration."""
    __tablename__ = "detector_models"

    model_id = Column(String(64), primary_key=True, default=lambda: f"mdl_{uuid.uuid4().hex[:8]}")
    model_name = Column(String(128), nullable=False)
    version = Column(String(32), nullable=False)
    training_date = Column(DateTime(timezone=True), default=utc_now)
    threshold = Column(Float, default=0.75)
    feature_set_json = Column(JSON, default=list)
    metrics_json = Column(JSON, default=dict)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)


class AgentModel(Base):
    """Stores registered AI agent identities, capabilities, trust tiers, and lifecycle states."""
    __tablename__ = "agents"

    agent_id = Column(String(64), primary_key=True, index=True)
    name = Column(String(128), nullable=False)
    role = Column(String(64), nullable=False, default="default_agent")
    agent_type = Column(String(64), default="assistant")
    owner = Column(String(64), default="system")
    capabilities_json = Column(JSON, default=list)
    trust_level = Column(String(32), default="STANDARD")
    trust_score = Column(Float, default=0.60)
    status = Column(String(32), default="ACTIVE", index=True)
    metadata_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)


class DelegationModel(Base):
    """Stores explicit agent-to-agent delegations, bounded capabilities, depth, and provenance."""
    __tablename__ = "delegations"

    delegation_id = Column(String(64), primary_key=True, index=True)
    source_agent_id = Column(String(64), nullable=False, index=True)
    target_agent_id = Column(String(64), nullable=False, index=True)
    session_id = Column(String(64), nullable=False, index=True)
    parent_delegation_id = Column(String(64), nullable=True)
    delegated_capabilities_json = Column(JSON, default=list)
    resource_scope = Column(String(256), default="*")
    delegation_depth = Column(Integer, default=1)
    status = Column(String(32), default="ACTIVE", index=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    provenance_chain_json = Column(JSON, default=list)
    metadata_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=utc_now)


class ExecutionModel(Base):
    """Stores execution audit trail, sandbox profile, duration, redactions, and outcomes."""
    __tablename__ = "executions"

    execution_id = Column(String(64), primary_key=True, index=True)
    session_id = Column(String(64), nullable=False, index=True)
    agent_id = Column(String(64), nullable=False, index=True)
    tool_name = Column(String(64), nullable=False, index=True)
    status = Column(String(32), default="COMPLETED", index=True)
    execution_backend = Column(String(32), default="IN_PROCESS_GUARDED")
    sandbox_profile = Column(String(32), default="STANDARD")
    execution_time_ms = Column(Float, default=0.0)
    exit_code = Column(Integer, default=0)
    redacted = Column(Boolean, default=False)
    detected_secrets_json = Column(JSON, default=list)
    error_message = Column(Text, nullable=True)
    sanitized_output_preview = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)


class AttackScenarioModel(Base):
    """Stores attack simulation scenario definitions, metadata, and expected baseline behaviors."""
    __tablename__ = "attack_scenarios"

    scenario_id = Column(String(64), primary_key=True, index=True)
    name = Column(String(128), nullable=False)
    category = Column(String(64), nullable=False, index=True)
    severity = Column(String(32), nullable=False, default="MEDIUM")
    objective = Column(String(64), nullable=False)
    description = Column(Text, default="")
    mitre_atlas_id = Column(String(64), default="UNMAPPED")
    owasp_llm_id = Column(String(64), default="UNMAPPED")
    expected_decision = Column(String(32), default="BLOCK")
    expected_detector = Column(String(128), default="")
    is_multi_step = Column(Boolean, default=False)
    enabled = Column(Boolean, default=True)
    metadata_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=utc_now)


class AttackRunModel(Base):
    """Stores full audit logs of attack simulation runs, baseline comparisons, and execution graphs."""
    __tablename__ = "attack_runs"

    run_id = Column(String(64), primary_key=True, index=True)
    scenario_id = Column(String(64), nullable=False, index=True)
    category = Column(String(64), nullable=False, index=True)
    baseline_type = Column(String(64), nullable=False, default="SYSTEM_D_FULL_AGENTSENTINEL")
    status = Column(String(32), nullable=False, default="COMPLETED")
    interrupted_at_step = Column(Integer, nullable=True)
    total_steps = Column(Integer, default=1)
    prevention_stage = Column(String(64), nullable=True)
    final_decision = Column(String(32), default="BLOCK")
    actual_decision = Column(String(32), default="BLOCK")
    is_successful_attack = Column(Boolean, default=False)
    execution_time_ms = Column(Float, default=0.0)
    step_results_json = Column(JSON, default=list)
    graph_nodes_json = Column(JSON, default=list)
    graph_edges_json = Column(JSON, default=list)
    summary_notes = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), default=utc_now)


class SecurityFindingModel(Base):
    """Stores structured threat findings, MITRE ATLAS/OWASP LLM mappings, and remediation guidance."""
    __tablename__ = "security_findings"

    finding_id = Column(String(64), primary_key=True, index=True)
    run_id = Column(String(64), nullable=False, index=True)
    scenario_id = Column(String(64), nullable=False, index=True)
    category = Column(String(64), nullable=False, index=True)
    severity = Column(String(32), nullable=False, default="HIGH")
    title = Column(String(256), nullable=False)
    description = Column(Text, default="")
    remediation = Column(Text, default="")
    mitre_atlas_id = Column(String(64), default="UNMAPPED")
    owasp_llm_id = Column(String(64), default="UNMAPPED")
    prevented_by = Column(String(128), default="POLICY_ENGINE")
    evidence_json = Column(JSON, default=list)
    created_at = Column(DateTime(timezone=True), default=utc_now)



