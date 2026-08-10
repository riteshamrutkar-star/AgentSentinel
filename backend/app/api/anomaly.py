from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.anomaly.detector import default_anomaly_detector
from app.db.crud import list_security_events
from app.db.models import ModelMetadataModel
from app.db.session import get_db

router = APIRouter(prefix="/api/v1/anomaly", tags=["Behavioral Anomaly Engine"])

@router.get("/session/{session_id}", summary="Get Session Behavioral Anomaly Analysis")
async def get_session_anomaly_analysis(
    session_id: str,
    db: Session = Depends(get_db)
):
    """
    Extracts behavioral features and calculates anomaly scores for a specified agent session.
    """
    events = list_security_events(db, session_id=session_id, limit=50)
    if not events:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No events found for session '{session_id}'."
        )

    last_event = events[0]
    features = default_anomaly_detector.extractor.extract_features(
        events=events[1:],
        current_tool_name=last_event.tool_name,
        current_role=last_event.role,
    )
    result = default_anomaly_detector.scorer.score_session_features(session_id, features)

    return {
        "session_id": session_id,
        "anomaly_score": result.anomaly_score,
        "anomaly_level": result.anomaly_level,
        "flagged": result.flagged,
        "reason": result.reason,
        "matched_pattern": result.matched_pattern,
        "recommended_action": result.recommended_action,
        "total_session_events": len(events),
        "features": features,
    }

@router.get("/models", summary="List Anomaly Detector Models Metadata")
async def list_detector_models(
    db: Session = Depends(get_db)
):
    """Lists registered anomaly detector model metadata records from PostgreSQL."""
    models = db.query(ModelMetadataModel).all()
    if not models:
        # Return default active detector info if DB table has no custom model rows yet
        return [
            {
                "model_id": "mdl_statistical_v1",
                "model_name": "Statistical & Heuristic Behavioral Sequence Scorer",
                "version": "1.0.0",
                "threshold": 0.65,
                "feature_set": [
                    "sequence_length", "denied_count", "sensitive_action_count",
                    "burst_count", "ratio_denied", "transition_penalty", "role_mismatch"
                ],
                "is_active": True,
            }
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
