"""
AgentSentinel Phase 0.9: Event Publishing & Fan-Out Engine.
Publishes versioned security events to Redis Pub/Sub for horizontal fan-out.

ARCHITECTURAL INVARIANT:
PostgreSQL remains the durable source of truth via the transactional outbox.
Redis Pub/Sub is used strictly for low-latency fan-out to connected SOC consoles
and distributed workers. If Redis fails, fan-out degrades gracefully while
durable events remain safely preserved in PostgreSQL.
"""

import json
import time
from typing import Any, Dict, Optional

from app.core.config import settings
from app.core.logger import logger
from app.distributed.redis import get_redis_client


class EventPublisher:
    """Publishes security events conforming to versioned envelope schema 1.0.0."""

    SCHEMA_VERSION = "1.0.0"

    @classmethod
    def format_envelope(cls, event_data: Dict[str, Any], namespace: str = "default") -> Dict[str, Any]:
        """Wraps raw event payload in a standardized metadata envelope."""
        return {
            "schema_version": cls.SCHEMA_VERSION,
            "publisher": "AgentSentinel",
            "namespace": namespace,
            "published_at": time.time(),
            "event": event_data,
        }

    @classmethod
    def publish(cls, event_data: Dict[str, Any], namespace: str = "default") -> bool:
        """
        Publishes event envelope to Redis Pub/Sub channels:
        - agentsentinel:events:<namespace>
        - agentsentinel:events:all
        Returns True if published to at least one subscriber/channel, False otherwise.
        """
        client = get_redis_client()
        if client is None:
            logger.debug("Redis client unavailable; event publishing skipped (durable outbox preserved).")
            return False

        envelope = cls.format_envelope(event_data, namespace)
        serialized = json.dumps(envelope, default=str)

        try:
            ns_channel = f"agentsentinel:events:{namespace}"
            all_channel = "agentsentinel:events:all"
            client.publish(ns_channel, serialized)
            client.publish(all_channel, serialized)
            logger.debug(f"Published event to Redis channels '{ns_channel}' and '{all_channel}'")
            return True
        except Exception as e:
            logger.warning(f"Event fan-out through Redis Pub/Sub encountered non-critical error: {e}")
            return False


    @classmethod
    def build_envelope(cls, event: Any, namespace: Optional[str] = None) -> Dict[str, Any]:
        """Builds a v1.0.0 standardized event envelope from a SecurityEvent or dictionary."""
        ns = namespace or getattr(event, "namespace", "default")
        if hasattr(event, "to_dict"):
            event_dict = event.to_dict()
        elif isinstance(event, dict):
            event_dict = event
        else:
            event_dict = dict(event)

        event_id = getattr(getattr(event, "identity", None), "event_id", "") or event_dict.get("identity", {}).get("event_id", "")
        return {
            "version": "1.0.0",
            "source": "agentsentinel-control-plane",
            "event_type": "SECURITY_EVENT",
            "namespace": ns,
            "event_id": event_id,
            "timestamp": time.time(),
            "data": event_dict,
        }


# Global singleton publisher
event_publisher = EventPublisher()
default_event_publisher = event_publisher
