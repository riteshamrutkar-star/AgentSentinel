"""
AgentSentinel Phase 0.9: Runtime Interceptor & Policy Engine Router.
Enforces durable namespace authorization, operator role validation, and failure isolation.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.audit.service import approve_action, reject_action
from app.auth.models import AdminRole, AuthenticatedIdentity
from app.auth.dependencies import get_current_identity, require_role, require_namespace_access
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
async def get_policy_rules(
    identity: AuthenticatedIdentity = Depends(get_current_identity),
):
    """Returns all active priority-ordered RBAC, ABAC, and Security Policy rules."""
    return default_policy_engine.rules


@router.post(
    "/intercept",
    response_model=InterceptorResponse,
    summary="Intercept Tool Call Request (Standard SDK Endpoint)",
)
@router.post(
    "/intercept/tool-call",
    response_model=InterceptorResponse,
    summary="Intercept Tool Call Request (Legacy Endpoint)",
)
async def handle_tool_call_interception(
    request: ToolCallRequest,
    identity: AuthenticatedIdentity = Depends(get_current_identity),
    db: Session = Depends(get_db),
):
    """
    Intercepts an AI Agent tool call request before execution.
    Enforces namespace access validation: identity must be authorized for requested namespace.
    Normalizes payload, evaluates policy rules, persists audit record in PostgreSQL,
    and returns a structured decision (ALLOW, BLOCK, REQUIRE_APPROVAL).
    """
    req_ns = getattr(request, "namespace", "default") or "default"

    # Durable Namespace Authorization Check
    if not identity.can_access_namespace(req_ns):
        logger.warning(
            f"Namespace Access Denied: Identity '{identity.identity_id}' attempted interception "
            f"in unauthorized namespace '{req_ns}'. Authorized: {identity.allowed_namespaces}"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Namespace authorization failed: Identity '{identity.identity_id}' is not authorized "
                f"for namespace '{req_ns}'. Authorized namespaces: {identity.allowed_namespaces}"
            ),
        )

    try:
        response = intercept_tool_call(request, db)
        return response
    except Exception as e:
        logger.error(f"Error in handle_tool_call_interception: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while intercepting the tool call.",
        )


@router.post("/intercept/decision", summary="Manual Approval Decision Override")
async def override_decision(
    override: DecisionOverrideRequest,
    identity: AuthenticatedIdentity = Depends(require_role(AdminRole.OPERATOR)),
    db: Session = Depends(get_db),
):
    """
    Provides human approval decision overrides on intercepted events.
    Enforces operator RBAC and verifies namespace authorization against the event's namespace.
    """
    event = get_security_event_by_id(db, override.event_id)
    if not event:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Security event '{override.event_id}' not found.")

    # Cross-namespace authorization check
    if not identity.can_access_namespace(event.namespace):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Namespace authorization failed: Identity '{identity.identity_id}' cannot mutate events in namespace '{event.namespace}'.",
        )

    dec = override.decision.strip().upper()
    try:
        if dec == "APPROVED":
            event = approve_action(db, event_id=override.event_id, reviewer=override.reviewer, notes=override.notes)
        elif dec == "REJECTED":
            event = reject_action(db, event_id=override.event_id, reviewer=override.reviewer, notes=override.notes)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid decision '{override.decision}'. Must be 'APPROVED' or 'REJECTED'.",
            )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        logger.error(f"Error executing override decision: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to process approval decision override.")

    return {
        "status": "success",
        "event_id": event.event_id,
        "namespace": event.namespace,
        "approval_status": event.approval_status,
        "execution_allowed": event.execution_allowed,
        "reviewer": event.reviewer,
        "decision_reason": event.decision_reason,
    }


@router.get("/intercept/events/{event_id}", summary="Get Intercepted Event Details")
async def get_intercepted_event(
    event_id: str,
    identity: AuthenticatedIdentity = Depends(get_current_identity),
    db: Session = Depends(get_db),
):
    """Retrieves full audited security event record by event_id with namespace check."""
    event = get_security_event_by_id(db, event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event '{event_id}' not found.",
        )

    if not identity.can_access_namespace(event.namespace):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Namespace authorization failed: Identity '{identity.identity_id}' cannot view events in namespace '{event.namespace}'.",
        )

    return {
        "event_id": event.event_id,
        "namespace": event.namespace,
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
