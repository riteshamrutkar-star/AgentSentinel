from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.audit.repository import (
    get_approval_by_event_id,
    get_approval_by_id,
    list_approvals,
    list_audit_events,
)
from app.audit.service import approve_action, reject_action
from app.db.crud import get_security_event_by_id
from app.db.session import get_db

router = APIRouter(prefix="/api/v1/audit", tags=["Audit Trails & Approvals"])

class ReviewActionRequest(BaseModel):
    reviewer: str = Field(..., description="Identity of human reviewer")
    notes: str = Field("", description="Reviewer comments or justification notes")

@router.get("/events", summary="List Audit Log Events")
async def get_audit_events(
    session_id: Optional[str] = Query(None, description="Filter by session ID"),
    decision_result: Optional[str] = Query(None, description="Filter by decision (ALLOW, DENY, REQUIRE_APPROVAL, APPROVED, REJECTED)"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Lists audit log event records with optional filters."""
    events = list_audit_events(db, session_id=session_id, decision_result=decision_result, limit=limit, offset=offset)
    return [
        {
            "event_id": e.event_id,
            "session_id": e.session_id,
            "agent_id": e.agent_id,
            "user_id": e.user_id,
            "tool_name": e.tool_name,
            "action_type": e.action_type,
            "decision_result": e.decision_result,
            "decision_reason": e.decision_reason,
            "approval_status": e.approval_status,
            "execution_allowed": e.execution_allowed,
            "reviewer": e.reviewer,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        }
        for e in events
    ]

@router.get("/events/{event_id}", summary="Get Audit Log Details for Event")
async def get_audit_event_details(
    event_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves full audited event record by event_id."""
    e = get_security_event_by_id(db, event_id)
    if not e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Audit event '{event_id}' not found.")

    return {
        "event_id": e.event_id,
        "session_id": e.session_id,
        "agent_id": e.agent_id,
        "user_id": e.user_id,
        "tool_name": e.tool_name,
        "action_type": e.action_type,
        "target_resource": e.target_resource,
        "arguments_payload": e.arguments_payload_json,
        "policy_result": e.policy_result,
        "decision_result": e.decision_result,
        "decision_reason": e.decision_reason,
        "approval_required": e.approval_required,
        "approval_status": e.approval_status,
        "execution_allowed": e.execution_allowed,
        "reviewer": e.reviewer,
        "threat_flags": e.threat_flags_json,
        "risk_indicators": e.risk_indicators_json,
        "anomaly_score": e.anomaly_score,
        "latency_ms": e.latency_ms,
        "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        "raw_payload": e.raw_payload_json,
    }

@router.get("/approvals", summary="List Approval Requests")
async def get_approval_requests(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (PENDING, APPROVED, REJECTED)"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Lists human approval request records."""
    approvals = list_approvals(db, status=status_filter, limit=limit, offset=offset)
    return [
        {
            "approval_id": a.approval_id,
            "event_id": a.event_id,
            "requested_at": a.requested_at.isoformat() if a.requested_at else None,
            "reviewed_at": a.reviewed_at.isoformat() if a.reviewed_at else None,
            "reviewer": a.reviewer,
            "decision": a.decision,
            "status": a.status,
            "notes": a.notes,
        }
        for a in approvals
    ]

@router.get("/approvals/{approval_id}", summary="Get Approval Record Details")
async def get_approval_details(
    approval_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves approval record details by approval_id."""
    a = get_approval_by_id(db, approval_id)
    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Approval record '{approval_id}' not found.")

    return {
        "approval_id": a.approval_id,
        "event_id": a.event_id,
        "requested_at": a.requested_at.isoformat() if a.requested_at else None,
        "reviewed_at": a.reviewed_at.isoformat() if a.reviewed_at else None,
        "reviewer": a.reviewer,
        "decision": a.decision,
        "status": a.status,
        "notes": a.notes,
    }

@router.post("/approvals/{event_id}/approve", summary="Approve Pending Action Request")
async def handle_approve_action(
    event_id: str,
    review: ReviewActionRequest,
    db: Session = Depends(get_db)
):
    """Approves a pending REQUIRE_APPROVAL action, updating event execution status to permitted."""
    try:
        updated_event = approve_action(db, event_id=event_id, reviewer=review.reviewer, notes=review.notes)
        return {
            "status": "success",
            "message": "Action successfully approved",
            "event_id": updated_event.event_id,
            "approval_status": updated_event.approval_status,
            "execution_allowed": updated_event.execution_allowed,
            "reviewer": updated_event.reviewer,
            "decision_reason": updated_event.decision_reason,
        }
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

@router.post("/approvals/{event_id}/reject", summary="Reject Pending Action Request")
async def handle_reject_action(
    event_id: str,
    review: ReviewActionRequest,
    db: Session = Depends(get_db)
):
    """Rejects a pending REQUIRE_APPROVAL action, keeping execution blocked."""
    try:
        updated_event = reject_action(db, event_id=event_id, reviewer=review.reviewer, notes=review.notes)
        return {
            "status": "success",
            "message": "Action successfully rejected",
            "event_id": updated_event.event_id,
            "approval_status": updated_event.approval_status,
            "execution_allowed": updated_event.execution_allowed,
            "reviewer": updated_event.reviewer,
            "decision_reason": updated_event.decision_reason,
        }
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
