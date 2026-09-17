"""
AgentSentinel Phase 0.9: SIEM Connector Foundation.
Provides integrations with enterprise SIEM aggregators (Datadog, Elastic, Splunk, Generic HTTP).
"""

import json
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import httpx

from app.core.config import settings
from app.core.logger import logger


class SIEMConnector(ABC):
    """Abstract interface for exporting security events to external SIEM platforms."""

    @abstractmethod
    def format_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Converts internal AgentSentinel event dict into target SIEM payload schema."""
        pass

    @abstractmethod
    def export_event(self, event_data: Dict[str, Any]) -> bool:
        """Transmits formatted event to remote SIEM aggregator endpoint."""
        pass


class GenericHTTPSIEMConnector(SIEMConnector):
    """
    Exports events in standard Common Event Format (CEF) / JSON to any generic HTTP log collector.
    Compatible with Splunk HTTP Event Collector (HEC) and Elastic Logstash HTTP input.
    """

    def __init__(
        self,
        endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        format: str = "JSON",
    ):
        self.endpoint = endpoint or settings.SIEM_ENDPOINT
        self.api_key = api_key or settings.SIEM_API_KEY
        self.format = format
        self._client: Optional[httpx.Client] = None

    def _get_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=5.0)
        return self._client

    def format_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        data = event_data.to_dict() if hasattr(event_data, "to_dict") else dict(event_data)
        identity = data.get("identity", {})
        decision = data.get("decision_context", {})
        tool = data.get("tool_action", {})
        security = data.get("security_context", {})

        return {
            "source": "AgentSentinel",
            "version": settings.APP_VERSION,
            "event_id": identity.get("event_id"),
            "timestamp": data.get("task_context", {}).get("timestamp"),
            "agent_id": identity.get("agent_id"),
            "user_id": identity.get("user_id"),
            "tool_name": tool.get("tool_name"),
            "verdict": decision.get("decision_result"),
            "decision_reason": decision.get("decision_reason"),
            "sensitivity": security.get("sensitivity_level"),
            "threat_flags": security.get("threat_flags", []),
            "anomaly_score": security.get("anomaly_score", 0.0),
            "namespace": data.get("namespace", "default"),
        }

    def format_cef(self, event_data: Any) -> str:
        """Formats event as ArcSight Common Event Format (CEF) standard string."""
        data = event_data.to_dict() if hasattr(event_data, "to_dict") else dict(event_data)
        identity = data.get("identity", {})
        decision = data.get("decision_context", {})
        tool = data.get("tool_action", {})

        event_id = identity.get("event_id", "evt_unknown")
        tool_name = tool.get("tool_name", "unknown_tool")
        verdict = decision.get("decision_result", "UNKNOWN")
        reason = decision.get("decision_reason", "")
        agent_id = identity.get("agent_id", "")

        return f"CEF:0|AgentSentinel|ControlPlane|{settings.APP_VERSION}|{verdict}|{tool_name}|5|suser={agent_id} msg={reason} cs1={event_id}"

    def export_event(self, event_data: Dict[str, Any]) -> bool:
        if not self.endpoint:
            logger.debug("GenericHTTPSIEMConnector: No endpoint configured; export skipped.")
            return False

        payload = self.format_event(event_data)
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            client = self._get_client()
            resp = client.post(self.endpoint, json=payload, headers=headers)
            if resp.is_success:
                logger.debug(f"SIEM export successful for event '{payload.get('event_id')}'")
                return True
            logger.warning(f"SIEM export failed (HTTP {resp.status_code}): {resp.text[:100]}")
            return False
        except Exception as e:
            logger.warning(f"Error exporting event to SIEM endpoint: {e}")
            return False


class DatadogSIEMConnector(SIEMConnector):
    """
    Exports events formatted for the Datadog Log Ingestion API.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        site: str = "datadoghq.com",
        service: str = "agentsentinel-controlplane",
    ):
        self.api_key = api_key or settings.SIEM_API_KEY
        self.site = site
        self.service = service
        self.endpoint = f"https://http-intake.logs.{site}/api/v2/logs"
        self._client: Optional[httpx.Client] = None

    def _get_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=5.0)
        return self._client

    def format_event(self, event_data: Any) -> Dict[str, Any]:
        data = event_data.to_dict() if hasattr(event_data, "to_dict") else dict(event_data)
        identity = data.get("identity", {})
        decision = data.get("decision_context", {})
        tool = data.get("tool_action", {})
        verdict = decision.get("decision_result", "ALLOW")
        agent_id = identity.get("agent_id", "")
        ns = data.get("namespace", "default")

        status_map = {
            "ALLOW": "info",
            "REQUIRE_APPROVAL": "warn",
            "BLOCK": "error",
            "DENY": "error",
        }

        return {
            "title": f"AgentSentinel Security Event: {tool.get('tool_name')} [{verdict}]",
            "ddsource": "agentsentinel",
            "service": self.service,
            "message": f"AgentSentinel Verdict [{verdict}]: Tool '{tool.get('tool_name')}' for Agent '{agent_id}'",
            "status": status_map.get(verdict, "info"),
            "alert_type": status_map.get(verdict, "info"),
            "tags": [agent_id, f"namespace:{ns}", f"verdict:{verdict}", f"env:{settings.ENVIRONMENT}"],
            "ddtags": f"env:{settings.ENVIRONMENT},agent:{agent_id},verdict:{verdict},namespace:{ns}",
            "event_details": data,
        }

    build_datadog_event = format_event

    def export_event(self, event_data: Dict[str, Any]) -> bool:
        if not self.api_key:
            return False

        payload = self.format_event(event_data)
        headers = {
            "Content-Type": "application/json",
            "DD-API-KEY": self.api_key,
        }

        try:
            client = self._get_client()
            resp = client.post(self.endpoint, json=payload, headers=headers)
            return resp.is_success
        except Exception as e:
            logger.warning(f"Datadog SIEM export error: {e}")
            return False


def get_siem_connector() -> SIEMConnector:
    """Factory resolving configured SIEM connector."""
    if settings.SIEM_TYPE == "datadog":
        return DatadogSIEMConnector()
    return GenericHTTPSIEMConnector()
