"""
Risk Intelligence REST API Endpoints for AgentSentinel Phase 0.3.
Provides detailed multi-detector risk decomposition, baseline deviation, and ad-hoc risk analysis.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.anomaly.engine import UnifiedRiskScore, default_risk_engine
from app.db.crud import list_security_events
from app.db.session import get_db
from app.interceptor.normalizer import normalize_tool_call_request
from app.interceptor.schema import ToolCallRequest

router = APIRouter(prefix="/api/v1/risk", tags=["Risk Intelligence Engine"])

class RiskAnalysisRequest(BaseModel):
    """Payload for on-demand tool call risk analysis."""
    session_id: str = Field(..., description="Target session identifier")
    tool_name: str = Field(..., description="Tool to evaluate")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Tool invocation parameters")
    role: str = Field("research_assistant", description="Agent security role")
    target_resource: Optional[str] = Field("", description="Target URI or resource path")
    action_type: Optional[str] = Field("UNKNOWN", description="Action category (READ, WRITE, NETWORK, DATABASE)")

@router.get("/session/{session_id}", response_model=UnifiedRiskScore, summary="Get Session Multi-Signal Risk Breakdown")
async def get_session_risk_breakdown(
    session_id: str,
    db: Session = Depends(get_db)
):
    """
    Returns full multi-detector behavioral risk breakdown for an active session,
    including individual detector outputs, contributions, top risk factors, and evidence.
    """
    events = list_security_events(db, session_id=session_id, limit=50)
    if not events:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No security events found for session '{session_id}'."
        )

    last_event_db = events[0]
    # Reconstruct SecurityEvent proxy representation from last event
    req = ToolCallRequest(
        session_id=last_event_db.session_id,
        agent_id=last_event_db.agent_id,
        user_id=last_event_db.user_id,
        tool_name=last_event_db.tool_name,
        arguments=last_event_db.arguments_payload_json or {},
        role=last_event_db.role,
        target_resource=last_event_db.target_resource,
        action_type=last_event_db.action_type,
    )
    security_event = normalize_tool_call_request(req)

    risk_score = default_risk_engine.evaluate_risk(
        event=security_event,
        history=events[1:]
    )

    return risk_score

@router.post("/analyze", response_model=UnifiedRiskScore, summary="On-Demand Tool Call Risk Analysis")
async def analyze_prospective_tool_call(
    request: RiskAnalysisRequest,
    db: Session = Depends(get_db)
):
    """
    Simulates and evaluates behavioral risk for a prospective tool invocation
    against historical session context without persisting changes.
    """
    events = list_security_events(db, session_id=request.session_id, limit=50)

    req = ToolCallRequest(
        session_id=request.session_id,
        agent_id="eval_agent",
        user_id="eval_user",
        tool_name=request.tool_name,
        arguments=request.arguments,
        role=request.role,
        target_resource=request.target_resource or "",
        action_type=request.action_type or "UNKNOWN",
    )
    security_event = normalize_tool_call_request(req)

    risk_score = default_risk_engine.evaluate_risk(
        event=security_event,
        history=events
    )

    return risk_score
