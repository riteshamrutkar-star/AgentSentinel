"""
AgentSentinel Phase 0.8: Security Alerts API Router.
Provides list, acknowledge, and resolve endpoints for SOC operators.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.crud import list_security_alerts, update_security_alert_status
from app.auth.models import AdminRole, AuthenticatedIdentity
from app.auth.dependencies import get_current_identity, require_role
from app.alerts.models import (
    AlertSeverity,
    AlertStatus,
    SecurityAlertResponse,
    AlertAcknowledgeRequest,
    AlertResolveRequest,
)

router = APIRouter(prefix="/api/v1/alerts", tags=["Security Alerts & Incident Management"])


@router.get(
    "",
    response_model=List[SecurityAlertResponse],
    summary="List active operational security alerts",
)
def get_alerts(
    status_filter: Optional[AlertStatus] = Query(default=None, alias="status"),
    severity_filter: Optional[AlertSeverity] = Query(default=None, alias="severity"),
    limit: int = Query(default=50, ge=1, le=200),
    identity: AuthenticatedIdentity = Depends(require_role(AdminRole.VIEWER)),
    db: Session = Depends(get_db),
):
    """Retrieves operational security alerts with optional severity and status filtering."""
    records = list_security_alerts(
        db=db,
        status=status_filter.value if status_filter else None,
        severity=severity_filter.value if severity_filter else None,
        limit=limit,
    )
    return [
        SecurityAlertResponse(
            alert_id=r.alert_id,
            alert_type=r.alert_type,
            severity=AlertSeverity(r.severity),
            title=r.title,
            description=r.description or "",
            source_event_id=r.source_event_id,
            source_agent_id=r.source_agent_id,
            threat_category=r.threat_category,
            status=AlertStatus(r.status),
            occurrence_count=r.occurrence_count,
            first_seen_at=r.first_seen_at,
            last_seen_at=r.last_seen_at,
            resolved_at=r.resolved_at,
            resolved_by=r.resolved_by,
            resolution_notes=r.resolution_notes,
        )
        for r in records
    ]


@router.post(
    "/{alert_id}/acknowledge",
    response_model=SecurityAlertResponse,
    summary="Acknowledge a security alert (Operator or higher)",
)
def acknowledge_alert(
    alert_id: str,
    payload: AlertAcknowledgeRequest,
    identity: AuthenticatedIdentity = Depends(require_role(AdminRole.OPERATOR)),
    db: Session = Depends(get_db),
):
    """Marks a new alert as acknowledged by a SOC operator."""
    updated = update_security_alert_status(
        db=db,
        alert_id=alert_id,
        status="ACKNOWLEDGED",
        operator_id=payload.acknowledged_by or payload.operator_id or identity.name,
    )
    if not updated:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")

    return SecurityAlertResponse(
        alert_id=updated.alert_id,
        alert_type=updated.alert_type,
        severity=AlertSeverity(updated.severity),
        title=updated.title,
        description=updated.description or "",
        source_event_id=updated.source_event_id,
        source_agent_id=updated.source_agent_id,
        threat_category=updated.threat_category,
        status=AlertStatus(updated.status),
        occurrence_count=updated.occurrence_count,
        first_seen_at=updated.first_seen_at,
        last_seen_at=updated.last_seen_at,
        resolved_at=updated.resolved_at,
        resolved_by=updated.resolved_by,
        resolution_notes=updated.resolution_notes,
    )


@router.post(
    "/{alert_id}/resolve",
    response_model=SecurityAlertResponse,
    summary="Resolve an active security alert (Operator or higher)",
)
def resolve_alert(
    alert_id: str,
    payload: AlertResolveRequest,
    identity: AuthenticatedIdentity = Depends(require_role(AdminRole.OPERATOR)),
    db: Session = Depends(get_db),
):
    """Marks an alert resolved and records operator resolution notes."""
    updated = update_security_alert_status(
        db=db,
        alert_id=alert_id,
        status="RESOLVED",
        operator_id=payload.resolved_by or payload.operator_id or identity.name,
        notes=payload.resolution_notes,
    )
    if not updated:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")

    return SecurityAlertResponse(
        alert_id=updated.alert_id,
        alert_type=updated.alert_type,
        severity=AlertSeverity(updated.severity),
        title=updated.title,
        description=updated.description or "",
        source_event_id=updated.source_event_id,
        source_agent_id=updated.source_agent_id,
        threat_category=updated.threat_category,
        status=AlertStatus(updated.status),
        occurrence_count=updated.occurrence_count,
        first_seen_at=updated.first_seen_at,
        last_seen_at=updated.last_seen_at,
        resolved_at=updated.resolved_at,
        resolved_by=updated.resolved_by,
        resolution_notes=updated.resolution_notes,
    )