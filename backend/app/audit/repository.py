from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy.orm import Session
from app.db.models import ApprovalModel, EventModel

def create_approval_request(db: Session, event_id: str) -> ApprovalModel:
    """Creates a new approval request record in PostgreSQL for a REQUIRE_APPROVAL event."""
    existing = db.query(ApprovalModel).filter(ApprovalModel.event_id == event_id).first()
    if existing:
        return existing

    approval = ApprovalModel(
        event_id=event_id,
        requested_at=datetime.now(timezone.utc),
        status="PENDING",
        decision="PENDING",
    )
    db.add(approval)
    db.commit()
    db.refresh(approval)
    return approval

def get_approval_by_id(db: Session, approval_id: str) -> Optional[ApprovalModel]:
    """Retrieves an approval record by approval_id."""
    return db.query(ApprovalModel).filter(ApprovalModel.approval_id == approval_id).first()

def get_approval_by_event_id(db: Session, event_id: str) -> Optional[ApprovalModel]:
    """Retrieves an approval record by event_id."""
    return db.query(ApprovalModel).filter(ApprovalModel.event_id == event_id).first()

def list_approvals(
    db: Session,
    status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
) -> List[ApprovalModel]:
    """Lists approval records with optional status filtering."""
    query = db.query(ApprovalModel)
    if status:
        query = query.filter(ApprovalModel.status == status.upper())
    return query.order_by(ApprovalModel.requested_at.desc()).offset(offset).limit(limit).all()

def update_approval_status(
    db: Session,
    event_id: str,
    status: str,
    reviewer: str,
    notes: str = ""
) -> Optional[ApprovalModel]:
    """Updates an approval record decision status, reviewer identity, and notes."""
    approval = db.query(ApprovalModel).filter(ApprovalModel.event_id == event_id).first()
    if not approval:
        approval = create_approval_request(db, event_id)

    now = datetime.now(timezone.utc)
    approval.status = status.upper()
    approval.decision = status.upper()
    approval.reviewer = reviewer
    approval.notes = notes
    approval.reviewed_at = now

    db.commit()
    db.refresh(approval)
    return approval

def list_audit_events(
    db: Session,
    session_id: Optional[str] = None,
    decision_result: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
) -> List[EventModel]:
    """Retrieves audited security events with optional session or verdict filters."""
    query = db.query(EventModel)
    if session_id:
        query = query.filter(EventModel.session_id == session_id)
    if decision_result:
        query = query.filter(EventModel.decision_result == decision_result.upper())
    return query.order_by(EventModel.timestamp.desc()).offset(offset).limit(limit).all()
