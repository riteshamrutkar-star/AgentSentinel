from typing import Optional
from sqlalchemy.orm import Session
from app.audit.logger import audit_logger
from app.audit.repository import (
    create_approval_request,
    get_approval_by_event_id,
    update_approval_status,
)
from app.db.crud import get_security_event_by_id, save_security_event
from app.db.models import EventModel
from app.events.model import SecurityEvent

def record_audit_entry(db: Session, security_event: SecurityEvent) -> EventModel:
    """
    Records an intercepted tool call security event into PostgreSQL audit storage.
    If human approval is required, provisions a pending ApprovalModel request.
    """
    event_id = security_event.identity.event_id
    tool_name = security_event.tool_action.tool_name
    agent_id = security_event.identity.agent_id
    verdict = security_event.decision_context.policy_result.value

    audit_logger.info(
        f"Event={event_id} | Agent={agent_id} | Tool={tool_name} | Verdict={verdict} | "
        f"ApprovalReq={security_event.decision_context.approval_required}"
    )

    # Persist event through Phase 3B CRUD layer
    db_event = save_security_event(db, security_event)

    # If approval required, create approval request record
    if security_event.decision_context.approval_required:
        create_approval_request(db, event_id)

    return db_event

def approve_action(db: Session, event_id: str, reviewer: str, notes: str = "") -> EventModel:
    """
    Approves a pending action request.
    Updates ApprovalModel and EventModel in PostgreSQL, enabling tool execution.
    """
    event = get_security_event_by_id(db, event_id)
    if not event:
        raise ValueError(f"Security event '{event_id}' not found.")

    # 1. Update ApprovalModel record
    update_approval_status(db, event_id=event_id, status="APPROVED", reviewer=reviewer, notes=notes)

    # 2. Update EventModel record
    event.approval_status = "APPROVED"
    event.execution_allowed = True
    event.decision_result = "APPROVED"
    event.reviewer = reviewer
    event.decision_reason = f"Human approval granted by {reviewer}. Notes: {notes or 'None'}"

    db.commit()
    db.refresh(event)

    audit_logger.info(f"APPROVAL GRANTED | Event={event_id} | Reviewer={reviewer} | Notes='{notes}'")
    return event

def reject_action(db: Session, event_id: str, reviewer: str, notes: str = "") -> EventModel:
    """
    Rejects a pending action request.
    Updates ApprovalModel and EventModel in PostgreSQL, keeping execution blocked.
    """
    event = get_security_event_by_id(db, event_id)
    if not event:
        raise ValueError(f"Security event '{event_id}' not found.")

    # 1. Update ApprovalModel record
    update_approval_status(db, event_id=event_id, status="REJECTED", reviewer=reviewer, notes=notes)

    # 2. Update EventModel record
    event.approval_status = "REJECTED"
    event.execution_allowed = False
    event.decision_result = "REJECTED"
    event.reviewer = reviewer
    event.decision_reason = f"Human approval rejected by {reviewer}. Notes: {notes or 'None'}"

    db.commit()
    db.refresh(event)

    audit_logger.info(f"APPROVAL REJECTED | Event={event_id} | Reviewer={reviewer} | Notes='{notes}'")
    return event
