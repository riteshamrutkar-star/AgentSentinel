"""
AgentSentinel Phase 0.9: Signed Webhooks & Durable Delivery Engine.
Provides HMAC-SHA-256 webhook signing, replay attack protection, and
crash-resilient PostgreSQL-backed delivery tracking that survives process restarts.

MANDATORY RELIABILITY GUARANTEES:
1. Webhook state is persisted in PostgreSQL (delivery_id, attempt_count, next_attempt_at, status).
2. Webhook delivery is strictly isolated from the primary security interception latency path.
3. Signature calculation incorporates timestamp to defeat replay attacks.
"""

import hmac
import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session
import httpx

from app.core.config import settings
from app.core.logger import logger
from app.db.models import WebhookDeliveryModel, EventModel


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def compute_webhook_signature(payload_str: str, secret: str, timestamp_str: str) -> str:
    """
    Computes HMAC-SHA-256 signature binding timestamp and payload.
    Signature format: sha256=<hex_digest>
    """
    signed_payload = f"{timestamp_str}.{payload_str}".encode("utf-8")
    secret_bytes = secret.encode("utf-8")
    digest = hmac.new(secret_bytes, signed_payload, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def verify_webhook_signature(
    payload_str: str,
    signature_header: str,
    timestamp_header: str,
    secret: str,
    tolerance_seconds: int = 300,
) -> bool:
    """
    Validates webhook signature and prevents replay attacks by rejecting timestamps outside tolerance.
    """
    if not signature_header or not timestamp_header or not secret:
        return False

    try:
        ts_float = float(timestamp_header)
    except ValueError:
        # Check if ISO format
        try:
            ts_dt = datetime.fromisoformat(timestamp_header.replace("Z", "+00:00"))
            ts_float = ts_dt.timestamp()
        except Exception:
            return False

    now_ts = time.time()
    if abs(now_ts - ts_float) > tolerance_seconds:
        logger.warning(f"Webhook signature rejected: timestamp {ts_float} outside tolerance window ({tolerance_seconds}s).")
        return False

    expected_sig = compute_webhook_signature(payload_str, secret, timestamp_header)
    return hmac.compare_digest(expected_sig, signature_header)


class WebhookDeliveryManager:
    """
    Manages durable asynchronous webhook delivery.
    Processes pending delivery attempts recorded in the database.
    """

    def __init__(self, client: Optional[httpx.Client] = None, secret: Optional[str] = None):
        self._client = client
        self.secret = secret or settings.WEBHOOK_SIGNING_SECRET

    def sign_payload(self, payload: Any, timestamp: Optional[float] = None) -> str:
        payload_str = json.dumps(payload, default=str) if not isinstance(payload, str) else payload
        ts_str = str(timestamp if timestamp is not None else time.time())
        return compute_webhook_signature(payload_str, self.secret, ts_str).replace("sha256=", "")

    def verify_signature(
        self,
        payload: Any,
        timestamp: float,
        signature: str,
        tolerance_seconds: int = 300,
    ) -> bool:
        payload_str = json.dumps(payload, default=str) if not isinstance(payload, str) else payload
        sig_header = f"sha256={signature}" if not signature.startswith("sha256=") else signature
        return verify_webhook_signature(
            payload_str=payload_str,
            signature_header=sig_header,
            timestamp_header=str(timestamp),
            secret=self.secret,
            tolerance_seconds=tolerance_seconds,
        )

    def get_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=settings.WEBHOOK_TIMEOUT_SECONDS)
        return self._client

    def deliver_batch(self, db: Session, max_batch: int = 25) -> int:
        """
        Polls durable database for due deliveries and attempts dispatch.
        Survives backend/process restarts.
        Returns count of successfully delivered webhooks.
        """
        now = utc_now()
        pending = (
            db.query(WebhookDeliveryModel)
            .filter(
                WebhookDeliveryModel.status.in_(["PENDING", "RETRYING"]),
                WebhookDeliveryModel.next_attempt_at <= now,
            )
            .order_by(WebhookDeliveryModel.created_at.asc())
            .limit(max_batch)
            .all()
        )

        if not pending:
            return 0

        delivered_count = 0
        client = self.get_client()

        for record in pending:
            event = db.query(EventModel).filter(EventModel.event_id == record.event_id).first()
            if not event:
                record.status = "FAILED"
                record.last_error = f"Source event '{record.event_id}' not found."
                record.completed_at = now
                continue

            payload_dict = event.raw_payload_json or {}
            payload_str = json.dumps(payload_dict, default=str)
            timestamp_str = str(time.time())
            signature = compute_webhook_signature(payload_str, settings.WEBHOOK_SIGNING_SECRET, timestamp_str)

            headers = {
                "Content-Type": "application/json",
                "User-Agent": "AgentSentinel-Webhook-Dispatcher/0.9",
                "X-AgentSentinel-Delivery-ID": record.delivery_id,
                "X-AgentSentinel-Event-ID": record.event_id,
                "X-AgentSentinel-Timestamp": timestamp_str,
                "X-AgentSentinel-Signature": signature,
                "X-AgentSentinel-Namespace": record.namespace,
            }

            record.attempt_count += 1

            try:
                resp = client.post(record.destination, content=payload_str, headers=headers)
                if resp.is_success:
                    record.status = "DELIVERED"
                    record.completed_at = utc_now()
                    record.last_error = None
                    delivered_count += 1
                    logger.info(f"Webhook delivery '{record.delivery_id}' delivered to '{record.destination}' (HTTP {resp.status_code})")
                else:
                    self._handle_failure(record, f"HTTP {resp.status_code}: {resp.text[:200]}")
            except Exception as e:
                self._handle_failure(record, str(e))

        try:
            db.commit()
        except Exception as commit_err:
            db.rollback()
            logger.error(f"Error persisting webhook delivery state: {commit_err}")

        return delivered_count

    def _handle_failure(self, record: WebhookDeliveryModel, error_msg: str) -> None:
        record.last_error = error_msg
        if record.attempt_count >= settings.WEBHOOK_MAX_RETRIES:
            record.status = "DEAD_LETTER"
            record.completed_at = utc_now()
            logger.error(
                f"Webhook delivery '{record.delivery_id}' to '{record.destination}' permanently failed "
                f"after {record.attempt_count} attempts: {error_msg}"
            )
        else:
            record.status = "RETRYING"
            # Exponential backoff: 2^attempt * 2 seconds
            delay = 2 ** record.attempt_count * 2
            record.next_attempt_at = utc_now() + timedelta(seconds=delay)
            logger.warning(
                f"Webhook delivery '{record.delivery_id}' failed (attempt {record.attempt_count}/{settings.WEBHOOK_MAX_RETRIES}). "
                f"Retrying in {delay}s: {error_msg}"
            )


# Global webhook manager
webhook_manager = WebhookDeliveryManager()
default_webhook_manager = webhook_manager
