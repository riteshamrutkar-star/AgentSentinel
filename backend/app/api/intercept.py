from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.audit.service import approve_action, reject_action
from app.core.logger import logger
from app.db.crud import get_security_event_by_id
from app.db.session import get_db
from app.interceptor.proxy import intercept_tool_call
from app.interceptor.schema import InterceptorResponse, ToolCallRequest
from app.policy.engine import default_policy_engine
from app.policy.schemas import PolicyRule

router = APIRouter(prefix="/api/v1", tags=["Runtime Interceptor & Policy Engine"])

class DecisionOverrideRequest(BaseModel):
    event_id: str = Field(..., description="Target security event UUID")
    decision: str = Field(..., description="New decision verdict: APPROVED or REJECTED")
    reviewer: str = Field(..., description="Human reviewer user ID")
    notes: str = Field("", description="Review notes")

@router.get("/intercept/health", summary="Interceptor Proxy Health Status")
async def interceptor_health():
    """Returns runtime proxy operational health status."""
    return {
        "status": "ok",
        "component": "AgentSentinel Runtime Interceptor Proxy & Policy Engine",
        "interception_mode": "ACTIVE_RBAC_ABAC_PRE_EXECUTION",
        "active_rules_count": len(default_policy_engine.rules),
    }

@router.get("/policy/rules", response_model=List[PolicyRule], summary="List Active RBAC/ABAC Security Policy Rules")
async def get_policy_rules():
    """Returns all active priority-ordered RBAC, ABAC, and Security Policy rules."""
    return default_policy_engine.rules

@router.post("/intercept/tool-call", response_model=InterceptorResponse, summary="Intercept Tool Call Request")
async def handle_tool_call_interception(
    request: ToolCallRequest,
    db: Session = Depends(get_db)
):
    """
    Intercepts an AI Agent tool call request before execution.
    Normalizes payload, evaluates Phase 5 RBAC/ABAC policy rules, persists audit record in PostgreSQL,
    and returns a structured decision (ALLOW, BLOCK, REQUIRE_APPROVAL).
    """
    try:
        response = intercept_tool_call(request, db)
        return response
    except Exception as e:
        logger.error(f"Error in handle_tool_call_interception: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while intercepting the tool call."
        )

@router.post("/intercept/decision", summary="Manual Approval Decision Override")
async def override_decision(
    override: DecisionOverrideRequest,
    db: Session = Depends(get_db)
):
    """
    Provides human approval decision overrides on intercepted events,
    delegating to the canonical audit approval service to ensure model synchronization.
    """
    dec = override.decision.strip().upper()
    try:
        if dec == "APPROVED":
            event = approve_action(db, event_id=override.event_id, reviewer=override.reviewer, notes=override.notes)
        elif dec == "REJECTED":
            event = reject_action(db, event_id=override.event_id, reviewer=override.reviewer, notes=override.notes)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid decision '{override.decision}'. Must be 'APPROVED' or 'REJECTED'."
            )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        logger.error(f"Error executing override decision: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to process approval decision override.")

    return {
        "status": "success",
        "event_id": event.event_id,
        "approval_status": event.approval_status,
        "execution_allowed": event.execution_allowed,
        "reviewer": event.reviewer,
        "decision_reason": event.decision_reason,
    }

@router.get("/intercept/events/{event_id}", summary="Get Intercepted Event Details")
async def get_intercepted_event(
    event_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves full audited security event record by event_id."""
    event = get_security_event_by_id(db, event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event '{event_id}' not found."
        )

    return {
        "event_id": event.event_id,
        "session_id": event.session_id,
        "agent_id": event.agent_id,
        "user_id": event.user_id,
        "tool_name": event.tool_name,
        "action_type": event.action_type,
        "target_resource": event.target_resource,
        "policy_result": event.policy_result,
        "decision_result": event.decision_result,
        "decision_reason": event.decision_reason,
        "execution_allowed": event.execution_allowed,
        "threat_flags": event.threat_flags_json,
        "risk_indicators": event.risk_indicators_json,
        "anomaly_score": event.anomaly_score,
        "latency_ms": event.latency_ms,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "raw_payload": event.raw_payload_json,
    }
