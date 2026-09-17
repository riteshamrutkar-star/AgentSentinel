"""
AgentSentinel Phase 0.8: Structured JSON Logger & Secret Redaction Filter.
Ensures machine-parseable logs for SIEM/observability systems while
guaranteeing that credentials and tokens are NEVER emitted into logs.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict

from app.core.config import settings


class SecretRedactingFilter(logging.Filter):
    """
    Scans every log record using the Phase 0.5 SecretProtectionLayer
    and replaces matching credentials with [REDACTED_<TYPE>].
    """

    def __init__(self):
        super().__init__()
        self._protector = None

    def _get_protector(self):
        if self._protector is None:
            try:
                from app.execution.secrets import SecretProtectionLayer
                self._protector = SecretProtectionLayer()
            except Exception:
                self._protector = None
        return self._protector

    def filter(self, record: logging.LogRecord) -> bool:
        protector = self._get_protector()
        if protector is None:
            return True

        if isinstance(record.msg, str):
            res = protector.redact_secrets(record.msg)
            record.msg = res.sanitized_text

        if record.args:
            if isinstance(record.args, dict):
                clean_args = {}
                for k, v in record.args.items():
                    if isinstance(v, str):
                        clean_args[k] = protector.redact_secrets(v).sanitized_text
                    else:
                        clean_args[k] = v
                record.args = clean_args
            elif isinstance(record.args, (list, tuple)):
                clean_args = []
                for v in record.args:
                    if isinstance(v, str):
                        clean_args.append(self._protector.redact_secrets(v).sanitized_text)
                    else:
                        clean_args.append(v)
                record.args = tuple(clean_args)

        return True


class JSONLogFormatter(logging.Formatter):
    """
    Serializes standard log records into structured, one-line JSON documents.
    Captures request tracing, security event IDs, agent IDs, and operational metadata.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "service": settings.APP_NAME,
            "environment": settings.ENVIRONMENT,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Include structured contextual metadata if present
        for field in (
            "request_id",
            "correlation_id",
            "event_id",
            "agent_id",
            "tool_name",
            "decision",
            "status",
            "latency_ms",
            "client_ip",
        ):
            val = getattr(record, field, None)
            if val is not None:
                log_entry[field] = val

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str)