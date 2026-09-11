from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.anomaly.detector import default_anomaly_detector
from app.anomaly.engine import default_risk_engine
from app.db.crud import list_security_events
from app.db.models import ModelMetadataModel
from app.db.session import get_db
from app.interceptor.normalizer import normalize_tool_call_request
from app.interceptor.schema import ToolCallRequest

router = APIRouter(prefix="/api/v1/anomaly", tags=["Behavioral Anomaly Engine"])

@router.get("/session/{session_id}", summary="Get Session Behavioral Anomaly Analysis")
async def get_session_anomaly_analysis(
    session_id: str,
    db: Session = Depends(get_db)
):
    """
    Extracts behavioral features and calculates unified multi-signal risk scores
    for a specified agent session.
    """
    events = list_security_events(db, session_id=session_id, limit=50)
    if not events:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No events found for session '{session_id}'."
        )

    last_event = events[0]
    req = ToolCallRequest(
        session_id=last_event.session_id,
        agent_id=last_event.agent_id,
        user_id=last_event.user_id,
        tool_name=last_event.tool_name,
        arguments=last_event.arguments_payload_json or {},
        role=last_event.role,
        target_resource=last_event.target_resource,
        action_type=last_event.action_type,
    )
    security_event = normalize_tool_call_request(req)

    unified_risk = default_risk_engine.evaluate_risk(
        event=security_event,
        history=events[1:]
    )

    seq_res = unified_risk.detector_results.get("SequenceAnomalyDetector")
    matched_pattern = seq_res.metadata.get("matched_pattern") if seq_res else None

    return {
        "session_id": session_id,
        "anomaly_score": unified_risk.overall_score,
        "anomaly_level": unified_risk.severity.value,
        "flagged": unified_risk.overall_score >= 0.65,
        "reason": unified_risk.explanation,
        "matched_pattern": matched_pattern,
        "primary_detector": unified_risk.primary_detector,
        "top_risk_factors": unified_risk.top_risk_factors,
        "evidence": unified_risk.evidence,
        "recommended_action": unified_risk.recommended_action,
        "total_session_events": len(events),
        "features": unified_risk.detector_contributions,
    }

@router.get("/models", summary="List Anomaly Detector Models Metadata")
async def list_detector_models(
    db: Session = Depends(get_db)
):
    """Lists registered behavioral detector suite metadata."""
    models = db.query(ModelMetadataModel).all()
    if not models:
        # Return registered suite of 5 active Phase 0.3 detectors
        return [
            {
                "model_id": "mdl_statistical_v1",
                "model_name": "Statistical Baseline Reference Detector",
                "version": "1.0.0",
                "threshold": 0.65,
                "weight": 0.15,
                "feature_set": ["denied_count", "sensitive_count", "burst_count", "ratio_denied"],
                "is_active": True,
            },
            {
                "model_id": "mdl_sequence_v1",
                "model_name": "Multi-Step Sequence Anomaly Detector",
                "version": "1.0.0",
                "threshold": 0.70,
                "weight": 0.30,
                "feature_set": ["probe_to_exfiltrate", "recon_before_destruction", "progressive_escalation"],
                "is_active": True,
            },
            {
                "model_id": "mdl_burst_v1",
                "model_name": "Temporal Burst & Call Frequency Detector",
                "version": "1.0.0",
                "threshold": 0.60,
                "weight": 0.15,
                "feature_set": ["burst_window_seconds", "min_interval", "calls_last_minute", "repeat_tool_count"],
                "is_active": True,
            },
            {
                "model_id": "mdl_transition_v1",
                "model_name": "Pairwise Tool Transition Risk Detector",
                "version": "1.0.0",
                "threshold": 0.65,
                "weight": 0.20,
                "feature_set": ["transition_matrix", "cross_domain_shift", "pairwise_risk_weight"],
                "is_active": True,
            },
            {
                "model_id": "mdl_role_v1",
                "model_name": "Role Capability & Scope Mismatch Detector",
                "version": "1.0.0",
                "threshold": 0.70,
                "weight": 0.20,
                "feature_set": ["role_scope_boundary", "prohibited_tools", "privilege_overreach"],
                "is_active": True,
            },
        ]

    return [
        {
            "model_id": m.model_id,
            "model_name": m.model_name,
            "version": m.version,
            "training_date": m.training_date.isoformat() if m.training_date else None,
            "threshold": m.threshold,
            "feature_set": m.feature_set_json,
            "metrics": m.metrics_json,
            "is_active": m.is_active,
        }
        for m in models
    ]
