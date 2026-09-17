"""
AgentSentinel Phase 0.9: Explicit Scoped Idempotency Engine.
Guarantees at-most-once execution for dangerous state mutations across distributed nodes.

SCOPED IDENTIFIER:
Idempotency-Key -> operation + identity + endpoint scope -> deduplication state

ENDPOINTS REQUIRING OR SUPPORTING IDEMPOTENCY:
- Tool execution submissions (POST /api/v1/execution/submit)
- Human approval resolutions (POST /api/v1/audit/approvals/{approval_id}/resolve)
- State-changing alert actions (POST /api/v1/alerts/{alert_id}/action)
- Administrative key creation (POST /api/v1/admin/keys)

REPLAY & CONFLICT SEMANTICS:
1. First request executes normally; record enters IN_PROGRESS then COMPLETED.
2. Repeated request with identical key and identical payload returns cached response without duplicate execution.
3. Repeated request with identical key but conflicting payload raises IdempotencyConflictError (HTTP 409).
4. Request with distinct key executes independently.
5. In production mode, if Redis is down for critical mutations, fails closed with IdempotencyUnavailableError.
"""

import json
import hashlib
import time
from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional, Tuple

from app.core.config import settings
from app.core.logger import logger
from app.distributed.state import get_state_backend, DistributedStateBackend
from app.distributed.redis import RedisConnectionError

config = settings


class IdempotencyError(Exception):
    """Base exception for idempotency engine errors."""
    def __init__(self, message: str = "Idempotency error", status_code: int = 500):
        super().__init__(message)
        self.status_code = status_code


class IdempotencyConflictError(IdempotencyError):
    """Raised when an existing idempotency key is reused with a different request payload (HTTP 409)."""
    def __init__(self, message: str = "Idempotency key reused with differing payload.", status_code: int = 409):
        super().__init__(message, status_code=status_code)


class IdempotencyInProgressError(IdempotencyError):
    """Raised when a concurrent request with the same idempotency key is currently executing (HTTP 409/425)."""
    pass


class IdempotencyUnavailableError(IdempotencyError):
    """Raised in production when distributed idempotency backend is unreachable (HTTP 503 fail-closed)."""
    pass


class IdempotencyStatus:
    """Standardized lifecycle status values for idempotency records."""
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


@dataclass
class IdempotencyRecord:
    key: str
    scope: str
    payload_hash: str
    status: str  # "IN_PROGRESS", "COMPLETED", "FAILED"
    response_code: Optional[int] = None
    response_body: Optional[str] = None
    created_at: float = 0.0
    completed_at: Optional[float] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, data_str: str) -> "IdempotencyRecord":
        return cls(**json.loads(data_str))


def hash_payload(payload: Any) -> str:
    """Computes deterministic SHA-256 digest of request payload."""
    if payload is None:
        return hashlib.sha256(b"").hexdigest()
    if isinstance(payload, bytes):
        return hashlib.sha256(payload).hexdigest()
    if isinstance(payload, str):
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
    if isinstance(payload, (dict, list)):
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return hashlib.sha256(str(payload).encode("utf-8")).hexdigest()


class IdempotencyManager:
    """
    Coordinates request deduplication using distributed state.
    Key scope: idempotency:<scope>:<idempotency_key>
    """

    def __init__(
        self,
        backend: Optional[DistributedStateBackend] = None,
        ttl_in_progress_seconds: int = 300,   # 5 minutes for inflight requests
        ttl_completed_seconds: int = 86400,     # 24 hours for completed results
    ):
        self._backend = backend
        self.ttl_in_progress = ttl_in_progress_seconds
        self.ttl_completed = ttl_completed_seconds

    @property
    def backend(self) -> DistributedStateBackend:
        if self._backend is None:
            self._backend = get_state_backend()
        return self._backend

    def _format_storage_key(self, scope: str, idempotency_key: str) -> str:
        return f"idempotency:{scope}:{idempotency_key}"

    def check_or_start(
        self,
        idempotency_key: str,
        scope: str,
        payload: Any,
    ) -> Tuple[bool, Optional[IdempotencyRecord]]:
        """
        Evaluates idempotency for incoming request:
        Returns:
          - (True, record) if already COMPLETED with matching payload -> return cached response.
          - (False, None) if NEW request -> claim IN_PROGRESS status and proceed to execute.
        Raises:
          - IdempotencyConflictError if key reused with conflicting payload.
          - IdempotencyInProgressError if key is currently being processed.
          - IdempotencyUnavailableError if production distributed state is down.
        """
        if not idempotency_key:
            return False, None

        storage_key = self._format_storage_key(scope, idempotency_key)
        payload_digest = hash_payload(payload)

        try:
            raw = self.backend.get(storage_key)
        except RedisConnectionError as rce:
            logger.critical(f"Fail-closed idempotency requirement: {rce}")
            raise IdempotencyUnavailableError("Distributed idempotency coordination unavailable in production.")
        except Exception as e:
            if settings.is_production:
                raise IdempotencyUnavailableError(f"Idempotency backend failure: {e}")
            logger.warning(f"Idempotency check error: {e}")
            return False, None

        if raw is not None:
            try:
                existing = IdempotencyRecord.from_json(raw)
            except Exception:
                existing = None

            if existing:
                # 1. Conflict detection: same key, different payload
                if existing.payload_hash != payload_digest:
                    logger.warning(
                        f"Idempotency Conflict: Key '{idempotency_key}' in scope '{scope}' "
                        f"presented with conflicting payload digest."
                    )
                    raise IdempotencyConflictError(
                        f"Idempotency key '{idempotency_key}' already used with different request parameters."
                    )

                # 2. Concurrency detection: request still in progress
                if existing.status == "IN_PROGRESS":
                    raise IdempotencyInProgressError(
                        f"Operation with idempotency key '{idempotency_key}' is currently executing."
                    )

                # 3. Cache hit: request completed
                if existing.status == "COMPLETED":
                    logger.info(f"Idempotency Cache Hit: Key '{idempotency_key}' returning cached response.")
                    return True, existing

        # New request: claim IN_PROGRESS state
        new_record = IdempotencyRecord(
            key=idempotency_key,
            scope=scope,
            payload_hash=payload_digest,
            status="IN_PROGRESS",
            created_at=time.time(),
        )

        try:
            self.backend.set(storage_key, new_record.to_json(), expire_seconds=self.ttl_in_progress)
        except RedisConnectionError as rce:
            raise IdempotencyUnavailableError(f"Cannot register in-progress idempotency key in production: {rce}")
        except Exception as e:
            if settings.is_production:
                raise IdempotencyUnavailableError(f"Idempotency set error: {e}")

        return False, None

    def complete(
        self,
        idempotency_key: str,
        scope: str,
        response_code: int,
        response_body: str,
    ) -> None:
        """Records successful execution result for future deduplication."""
        if not idempotency_key:
            return

        storage_key = self._format_storage_key(scope, idempotency_key)
        try:
            raw = self.backend.get(storage_key)
            record = IdempotencyRecord.from_json(raw) if raw else None
        except Exception:
            record = None

        if record:
            record.status = "COMPLETED"
            record.response_code = response_code
            record.response_body = response_body
            record.completed_at = time.time()
            data = record.to_json()
        else:
            data = IdempotencyRecord(
                key=idempotency_key,
                scope=scope,
                payload_hash="",
                status="COMPLETED",
                response_code=response_code,
                response_body=response_body,
                created_at=time.time(),
                completed_at=time.time(),
            ).to_json()

        try:
            self.backend.set(storage_key, data, expire_seconds=self.ttl_completed)
        except Exception as e:
            logger.warning(f"Error completing idempotency record '{idempotency_key}': {e}")

    def execute_idempotent(
        self,
        key: str,
        operation: str,
        identity: str,
        endpoint: str,
        payload: Any,
        fn: Any,
    ) -> Tuple[Any, bool]:
        """
        Coordinates full idempotent execution:
        - If already executed with identical payload, returns (cached_response, True).
        - If new, executes `fn()`, records completion, and returns (response, False).
        - If conflict or production backend failure, raises appropriate exception.
        """
        scope = f"{operation}:{identity}:{endpoint}"
        storage_key = self._format_storage_key(scope, key)
        payload_digest = hash_payload(payload)

        # Check production fail-closed
        env = getattr(config, "ENVIRONMENT", getattr(settings, "ENVIRONMENT", "development"))
        is_prod = env == "production"

        try:
            raw = self.backend.get(storage_key)
        except RedisConnectionError as rce:
            logger.critical(f"RedisConnectionError in IdempotencyManager: {rce}")
            if is_prod:
                raise IdempotencyConflictError(
                    f"Fail-closed: Distributed idempotency backend unreachable: {rce}",
                    status_code=503,
                )
            raw = None
        except Exception as e:
            if is_prod:
                raise IdempotencyConflictError(
                    f"Fail-closed: Idempotency error: {e}",
                    status_code=503,
                )
            raw = None

        if raw is not None:
            existing = IdempotencyRecord.from_json(raw)
            if existing.payload_hash != payload_digest:
                raise IdempotencyConflictError(
                    f"Idempotency key '{key}' already used with differing payload.",
                    status_code=409,
                )
            if existing.status == IdempotencyStatus.COMPLETED and existing.response_body:
                try:
                    return json.loads(existing.response_body), True
                except Exception:
                    return existing.response_body, True

        # Acquire lock to ensure exactly-once execution under concurrent replay storms
        from app.distributed.lock import DistributedLock

        with DistributedLock(name=f"idem:{storage_key}", backend=self.backend, ttl_seconds=10, timeout_seconds=10.0):
            # Double-check inside lock
            raw_locked = self.backend.get(storage_key)
            if raw_locked is not None:
                existing = IdempotencyRecord.from_json(raw_locked)
                if existing.payload_hash != payload_digest:
                    raise IdempotencyConflictError(
                        f"Idempotency key '{key}' already used with differing payload.",
                        status_code=409,
                    )
                if existing.status == IdempotencyStatus.COMPLETED and existing.response_body:
                    try:
                        return json.loads(existing.response_body), True
                    except Exception:
                        return existing.response_body, True

            # First execution:
            result = fn()
            record = IdempotencyRecord(
                key=key,
                scope=scope,
                payload_hash=payload_digest,
                status=IdempotencyStatus.COMPLETED,
                response_code=200,
                response_body=json.dumps(result) if not isinstance(result, str) else result,
                created_at=time.time(),
                completed_at=time.time(),
            )
            try:
                self.backend.set(storage_key, record.to_json(), expire_seconds=self.ttl_completed)
            except Exception as e:
                if is_prod:
                    raise IdempotencyConflictError(f"Fail-closed: could not persist idempotency: {e}", status_code=503)
            return result, False

    def fail(self, idempotency_key: str, scope: str) -> None:
        """Clears or marks failed idempotency record allowing caller retries."""
        if not idempotency_key:
            return
        storage_key = self._format_storage_key(scope, idempotency_key)
        try:
            self.backend.delete(storage_key)
        except Exception as e:
            logger.warning(f"Error evicting failed idempotency key '{idempotency_key}': {e}")


# Global idempotency manager
global_idempotency_manager = IdempotencyManager()
default_idempotency_manager = global_idempotency_manager
idempotency_manager = global_idempotency_manager
