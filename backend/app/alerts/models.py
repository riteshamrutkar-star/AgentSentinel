"""
AgentSentinel Phase 0.8: Security Alerting Domain Models.
Defines alert severities, lifecycle triage states, and operational schemas.
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class AlertSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, Enum):
    NEW = "NEW"
    ACTIVE = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    DISMISSED = "DISMISSED"


class SecurityAlertResponse(BaseModel):
    alert_id: str
    alert_type: str
    severity: AlertSeverity
    title: str
    description: str
    source_event_id: Optional[str] = None
    source_agent_id: Optional[str] = None
    threat_category: Optional[str] = None
    status: AlertStatus
    occurrence_count: int
    namespace: str = "default"
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    resolution_notes: Optional[str] = None


class AlertAcknowledgeRequest(BaseModel):
    operator_id: Optional[str] = Field(default="soc_operator", description="Operator identity acknowledging alert")
    acknowledged_by: Optional[str] = Field(default=None, description="Operator name or identifier")


class AlertResolveRequest(BaseModel):
    operator_id: Optional[str] = Field(default="soc_operator", description="Operator identity resolving alert")
    resolved_by: Optional[str] = Field(default=None, description="Operator name or identifier")
    resolution_notes: Optional[str] = Field(default="", description="Operator resolution narrative")