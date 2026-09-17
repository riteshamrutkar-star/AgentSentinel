"""
AgentSentinel Phase 0.8: Security Alert Engine.
Aggregates, ranks, deduplicates, and manages operational security alerts.
Integrates with Prometheus metrics and PostgreSQL persistence.
"""

import uuid
from typing import Optional, List
from sqlalchemy.orm import Session

from app.core.logger import logger
from app.observability.metrics import metrics_registry
from app.db.models import SecurityAlertModel
from app.db.crud import (
    create_or_update_security_alert,
    list_security_alerts,
    update_security_alert_status,
)
from app.alerts.models import AlertSeverity, AlertStatus


class SecurityAlertEngine:
    """Core operational security alert manager."""

    def __init__(self, db: Optional[Session] = None):
        self.db = db

    def trigger_alert(
        self,
        alert_type: str,
        severity: AlertSeverity,
        title: str,
        description: str = "",
        source_event_id: Optional[str] = None,
        source_agent_id: Optional[str] = None,
        threat_category: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> Optional[SecurityAlertModel]:
        return self.raise_alert(
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=description,
            source_event_id=source_event_id,
            source_agent_id=source_agent_id,
            threat_category=threat_category,
            db=self.db,
        )

    def acknowledge_alert(self, alert_id: str, acknowledged_by: str = "operator") -> Optional[SecurityAlertModel]:
        return update_security_alert_status(
            db=self.db,
            alert_id=alert_id,
            status=AlertStatus.ACKNOWLEDGED.value,
            acknowledged_by=acknowledged_by,
        )

    def resolve_alert(
        self,
        alert_id: str,
        resolved_by: str = "admin",
        resolution_notes: str = "",
    ) -> Optional[SecurityAlertModel]:
        return update_security_alert_status(
            db=self.db,
            alert_id=alert_id,
            status=AlertStatus.RESOLVED.value,
            resolved_by=resolved_by,
            resolution_notes=resolution_notes,
        )

    @classmethod
    def raise_alert(
        cls,
        alert_type: str,
        severity: AlertSeverity,
        title: str,
        description: str = "",
        source_event_id: Optional[str] = None,
        source_agent_id: Optional[str] = None,
        threat_category: Optional[str] = None,
        db: Optional[Session] = None,
    ) -> Optional[SecurityAlertModel]:
        """
        Raises an operational security alert.
        Deduplicates repeated alerts for the same agent/type and updates Prometheus counts.
        """
        alert_id = f"alt_{uuid.uuid4().hex[:10]}"
        record = create_or_update_security_alert(
            db=db,
            alert_id=alert_id,
            alert_type=alert_type,
            severity=severity.value,
            title=title,
            description=description,
            source_event_id=source_event_id,
            source_agent_id=source_agent_id,
            threat_category=threat_category,
        )

        metrics_registry.security_alerts_total.inc(severity=severity.value)
        logger.warning(
            f"SECURITY ALERT [{severity.value}] {alert_type}: {title} "
            f"(Agent: {source_agent_id or 'unknown'}, Event: {source_event_id or 'none'})"
        )
        return record

    @classmethod
    def check_and_alert_policy_block(
        cls,
        event_id: str,
        agent_id: str,
        tool_name: str,
        policy_name: str,
        db: Optional[Session] = None,
    ) -> Optional[SecurityAlertModel]:
        """Triggered when an adversarial action is blocked by policy."""
        return cls.raise_alert(
            alert_type="POLICY_VIOLATION_BLOCKED",
            severity=AlertSeverity.HIGH,
            title=f"Policy Block: Tool '{tool_name}' blocked for agent '{agent_id}'",
            description=f"Action blocked by policy [{policy_name}].",
            source_event_id=event_id,
            source_agent_id=agent_id,
            threat_category="POLICY_VIOLATION",
            db=db,
        )

    @classmethod
    def check_and_alert_critical_anomaly(
        cls,
        event_id: str,
        agent_id: str,
        anomaly_score: float,
        level: str,
        db: Optional[Session] = None,
    ) -> Optional[SecurityAlertModel]:
        """Triggered when behavioral anomaly engine flags a high or critical anomaly."""
        if anomaly_score >= 0.80 or level == "CRITICAL":
            return cls.raise_alert(
                alert_type="CRITICAL_BEHAVIORAL_ANOMALY",
                severity=AlertSeverity.CRITICAL if anomaly_score >= 0.90 else AlertSeverity.HIGH,
                title=f"Critical Behavioral Risk: Agent '{agent_id}' scored {anomaly_score:.3f}",
                description=f"Behavioral Anomaly Engine escalated session to {level} risk.",
                source_event_id=event_id,
                source_agent_id=agent_id,
                threat_category="BEHAVIORAL_ANOMALY",
                db=db,
            )
        return None

    @classmethod
    def check_and_alert_sandbox_escape(
        cls,
        event_id: str,
        agent_id: str,
        violation_reason: str,
        db: Optional[Session] = None,
    ) -> Optional[SecurityAlertModel]:
        """Triggered on path traversal or unauthorized subprocess execution attempt."""
        return cls.raise_alert(
            alert_type="SANDBOX_BOUNDARY_VIOLATION",
            severity=AlertSeverity.CRITICAL,
            title=f"Execution Boundary Violation: Agent '{agent_id}' breached sandbox rules",
            description=f"Sandbox containment policy intercepted: {violation_reason}",
            source_event_id=event_id,
            source_agent_id=agent_id,
            threat_category="SANDBOX_ESCAPE",
            db=db,
        )


alert_engine = SecurityAlertEngine()