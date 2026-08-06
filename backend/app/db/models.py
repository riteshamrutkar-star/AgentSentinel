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
    decision_result = Column(String(32), default="ALLOW")
    decision_reason = Column(Text, default="")
    approval_required = Column(Boolean, default=False)
    reviewer = Column(String(64), nullable=True)
    approval_status = Column(String(32), default="NOT_REQUIRED")

    # Execution Context Fields
    execution_allowed = Column(Boolean, default=True)
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

    created_at = Column(DateTime(timezone=True), default=utc_now)
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
    status = Column(String(32), default="PENDING")

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
