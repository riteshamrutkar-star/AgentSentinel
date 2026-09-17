"""
AgentSentinel Phase 0.9: Security Alerts API Router.
Provides list, acknowledge, resolve, and action mutation endpoints for SOC operators
with durable namespace boundaries and idempotency protection against duplicate replays.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.crud import list_security_alerts, update_security_alert_status
from app.db.models import SecurityAlertModel
from app.auth.models import AdminRole, AuthenticatedIdentity
from app.auth.dependencies import get_current_identity, require_role, require_namespace_access
from app.alerts.models import (
    AlertSeverity,
    AlertStatus,
    SecurityAlertResponse,
    AlertAcknowledgeRequest,
    AlertResolveRequest,
)

router = APIRouter(prefix="/api/v1/alerts", tags=["Security Alerts & Incident Management"])


class AlertActionRequest(BaseModel):
    action: str = Field(..., description="Action to perform: ACKNOWLEDGE, RESOLVE, or DISMISS")
    operator_id: Optional[str] = Field(default="soc_operator", description="Operator identity")
    notes: Optional[str] = Field(default="", description="Resolution narrative or notes")


@router.get(
    "",
    response_model=List[SecurityAlertResponse],
    summary="List active operational security alerts",
)
def get_alerts(
    status_filter: Optional[AlertStatus] = Query(default=None, alias="status"),
    severity_filter: Optional[AlertSeverity] = Query(default=None, alias="severity"),
    limit: int = Query(default=50, ge=1, le=200),
    x_namespace: Optional[str] = Header(default=None, alias="X-Namespace"),
    identity: AuthenticatedIdentity = Depends(require_role(AdminRole.VIEWER)),
    db: Session = Depends(get_db),
):
    """Retrieves operational security alerts scoped to the identity's authorized namespaces."""
    target_ns = x_namespace.strip() if x_namespace else None

    # Filter query
    query = db.query(SecurityAlertModel)
    if status_filter:
        query = query.filter(SecurityAlertModel.status == status_filter.value)
    if severity_filter:
        query = query.filter(SecurityAlertModel.severity == severity_filter.value)
    if target_ns:
        if not identity.can_access_namespace(target_ns):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Namespace authorization failed: Identity cannot access alerts in '{target_ns}'.",
            )
        query = query.filter(SecurityAlertModel.namespace == target_ns)
    elif "*" not in identity.allowed_namespaces:
        query = query.filter(SecurityAlertModel.namespace.in_(identity.allowed_namespaces))

    records = query.order_by(SecurityAlertModel.last_seen_at.desc()).limit(limit).all()

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
            namespace=getattr(r, "namespace", "default") or "default",
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
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    identity: AuthenticatedIdentity = Depends(require_role(AdminRole.OPERATOR)),
    db: Session = Depends(get_db),
):
    """Marks an alert as acknowledged with idempotency and namespace verification."""
    action_req = AlertActionRequest(
        action="ACKNOWLEDGE",
        operator_id=payload.acknowledged_by or payload.operator_id or identity.name,
    )
    return handle_alert_action(
        alert_id=alert_id,
        payload=action_req,
        idempotency_key=idempotency_key,
        identity=identity,
        db=db,
    )


@router.post(
    "/{alert_id}/resolve",
    response_model=SecurityAlertResponse,
    summary="Resolve an active security alert (Operator or higher)",
)
def resolve_alert(
    alert_id: str,
    payload: AlertResolveRequest,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    identity: AuthenticatedIdentity = Depends(require_role(AdminRole.OPERATOR)),
    db: Session = Depends(get_db),
):
    """Marks an alert resolved with idempotency and namespace verification."""
    action_req = AlertActionRequest(
        action="RESOLVE",
        operator_id=payload.resolved_by or payload.operator_id or identity.name,
        notes=payload.resolution_notes or "",
    )
    return handle_alert_action(
        alert_id=alert_id,
        payload=action_req,
        idempotency_key=idempotency_key,
        identity=identity,
        db=db,
    )


@router.post(
    "/{alert_id}/action",
    response_model=SecurityAlertResponse,
    summary="Execute state-changing alert action (Operator or higher with Idempotency)",
)
def handle_alert_action(
    alert_id: str,
    payload: AlertActionRequest,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    identity: AuthenticatedIdentity = Depends(require_role(AdminRole.OPERATOR)),
    db: Session = Depends(get_db),
):
    """
    State-changing alert mutation endpoint supporting ACKNOWLEDGE, RESOLVE, DISMISS.
    Guaranteed at-most-once execution via Idempotency-Key.
    """
    import json
    from app.distributed.idempotency import (
        global_idempotency_manager,
        IdempotencyConflictError,
        IdempotencyInProgressError,
        IdempotencyUnavailableError,
    )

    scope = f"alert_action:{alert_id}"

    if idempotency_key:
        try:
            cached, record = global_idempotency_manager.check_or_start(
                idempotency_key=idempotency_key,
                scope=scope,
                payload=payload.model_dump(),
            )
            if cached and record and record.response_body:
                cached_dict = json.loads(record.response_body)
                return SecurityAlertResponse(**cached_dict)
        except IdempotencyConflictError as ice:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(ice))
        except IdempotencyInProgressError as ipe:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(ipe))
        except IdempotencyUnavailableError as iue:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(iue))

    # Verify alert existence and namespace boundary
    alert_rec = db.query(SecurityAlertModel).filter(SecurityAlertModel.alert_id == alert_id).first()
    if not alert_rec:
        if idempotency_key:
            global_idempotency_manager.fail(idempotency_key, scope)
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")

    alert_ns = getattr(alert_rec, "namespace", "default") or "default"
    if not identity.can_access_namespace(alert_ns):
        if idempotency_key:
            global_idempotency_manager.fail(idempotency_key, scope)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Namespace authorization failed: Identity cannot mutate alert in namespace '{alert_ns}'.",
        )

    act = payload.action.strip().upper()
    status_map = {
        "ACKNOWLEDGE": "ACKNOWLEDGED",
        "RESOLVE": "RESOLVED",
        "DISMISS": "DISMISSED",
    }
    target_status = status_map.get(act, "ACKNOWLEDGED")

    updated = update_security_alert_status(
        db=db,
        alert_id=alert_id,
        status=target_status,
        operator_id=payload.operator_id or identity.name,
        notes=payload.notes,
    )

    res_obj = SecurityAlertResponse(
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
        namespace=alert_ns,
        first_seen_at=updated.first_seen_at,
        last_seen_at=updated.last_seen_at,
        resolved_at=updated.resolved_at,
        resolved_by=updated.resolved_by,
        resolution_notes=updated.resolution_notes,
    )

    if idempotency_key:
        global_idempotency_manager.complete(
            idempotency_key=idempotency_key,
            scope=scope,
            response_code=200,
            response_body=res_obj.model_dump_json(),
        )

    return res_obj