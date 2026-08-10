from typing import Any, Dict, List
from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.models import EventModel, SessionModel, ApprovalModel
from app.db.session import get_db

router = APIRouter(prefix="/api/v1/dashboard", tags=["Security Dashboard API"])

@router.get("/stats", summary="Get Live Security KPI Statistics")
async def get_dashboard_stats(db: Session = Depends(get_db)):
    """Returns aggregated KPI summary counts for the security dashboard."""
    total_events = db.query(func.count(EventModel.event_id)).scalar() or 0
    allowed_count = db.query(func.count(EventModel.event_id)).filter(EventModel.execution_allowed == True).scalar() or 0
    blocked_count = db.query(func.count(EventModel.event_id)).filter(EventModel.decision_result == "DENY").scalar() or 0
    pending_approval_count = db.query(func.count(ApprovalModel.approval_id)).filter(ApprovalModel.status == "PENDING").scalar() or 0
    active_session_count = db.query(func.count(SessionModel.session_id)).filter(SessionModel.status == "ACTIVE").scalar() or 0

    # Fallback to unique session IDs in events if sessions table count is zero
    if active_session_count == 0:
        active_session_count = db.query(func.count(func.distinct(EventModel.session_id))).scalar() or 0

    return {
        "total_events": total_events,
        "allowed_count": allowed_count,
        "blocked_count": blocked_count,
        "pending_approval_count": pending_approval_count,
        "active_session_count": active_session_count,
    }

@router.get("/activity-trend", summary="Get Security Activity Trend Data")
async def get_activity_trend(db: Session = Depends(get_db)):
    """Returns activity breakdown over time for live activity chart."""
    recent_events = db.query(EventModel).order_by(EventModel.created_at.desc()).limit(100).all()
    recent_events.reverse() # Oldest to newest for timeline

    trend_buckets: Dict[str, Dict[str, int]] = {}
    for evt in recent_events:
        # Group by HH:MM minute bucket
        bucket_key = evt.created_at.strftime("%H:%M") if evt.created_at else "Now"
        if bucket_key not in trend_buckets:
            trend_buckets[bucket_key] = {"allowed": 0, "blocked": 0, "approval": 0}

        if evt.decision_result == "ALLOW":
            trend_buckets[bucket_key]["allowed"] += 1
        elif evt.decision_result == "DENY":
            trend_buckets[bucket_key]["blocked"] += 1
        else:
            trend_buckets[bucket_key]["approval"] += 1

    chart_data = [
        {"time": k, "allowed": v["allowed"], "blocked": v["blocked"], "approval": v["approval"]}
        for k, v in trend_buckets.items()
    ]

    return chart_data[-15:] # Return last 15 time buckets

@router.get("/risk-summary", summary="Get Anomaly Risk Level Summary")
async def get_risk_summary(db: Session = Depends(get_db)):
    """Returns count breakdown of events by anomaly risk level."""
    events = db.query(EventModel).all()
    counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

    for evt in events:
        score = evt.anomaly_score or 0.0
        if score < 0.30:
            counts["LOW"] += 1
        elif score < 0.65:
            counts["MEDIUM"] += 1
        elif score < 0.85:
            counts["HIGH"] += 1
        else:
            counts["CRITICAL"] += 1

    total = len(events) or 1
    return {
        "counts": counts,
        "percentages": {
            k: round((v / total) * 100, 1) for k, v in counts.items()
        }
    }

@router.get("/active-sessions", summary="Get Active Sessions List")
async def get_active_sessions(db: Session = Depends(get_db)):
    """Returns list of active agent sessions."""
    # Query distinct sessions from EventModel
    rows = (
        db.query(
            EventModel.session_id,
            EventModel.agent_id,
            EventModel.role,
            func.max(EventModel.created_at).label("last_active")
        )
        .group_by(EventModel.session_id, EventModel.agent_id, EventModel.role)
        .order_by(func.max(EventModel.created_at).desc())
        .limit(10)
        .all()
    )

    return [
        {
            "session_id": r.session_id,
            "agent_id": r.agent_id,
            "role": r.role,
            "status": "ACTIVE",
            "last_active": r.last_active.strftime("%H:%M:%S") if r.last_active else "Now",
        }
        for r in rows
    ]
