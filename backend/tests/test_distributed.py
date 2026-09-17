"""
Unit and integration tests for AgentSentinel Phase 0.9: Distributed Control Plane.
Tests state backends, distributed locks, idempotency management, and rate limiting.
"""

import time
import pytest
from unittest.mock import MagicMock, patch

from app.distributed.state import (
    DistributedStateBackend,
    LocalStateBackend,
    RedisStateBackend,
    get_state_backend,
)
from app.distributed.lock import DistributedLock
from app.distributed.idempotency import (
    IdempotencyManager,
    IdempotencyConflictError,
    IdempotencyRecord,
    IdempotencyStatus,
    default_idempotency_manager,
)
from app.distributed.redis import RedisConnectionError
from app.core.ratelimit import RateLimiter, InMemoryRateLimiter


# --- 1. LocalStateBackend Tests ---

def test_local_state_backend_basic_kv():
    backend = LocalStateBackend()
    backend.set("test_key", "hello", expire_seconds=10)
    assert backend.get("test_key") == "hello"

    backend.delete("test_key")
    assert backend.get("test_key") is None


def test_local_state_backend_expiration():
    backend = LocalStateBackend()
    backend.set("exp_key", "val", expire_seconds=1)
    assert backend.get("exp_key") == "val"

    time.sleep(1.1)
    assert backend.get("exp_key") is None


def test_local_state_backend_sorted_set():
    backend = LocalStateBackend()
    now = time.time()
    backend.zadd("zkey", 10.0, "member1")
    backend.zadd("zkey", 20.0, "member2")
    backend.zadd("zkey", 30.0, "member3")

    assert backend.zcard("zkey") == 3

    # Remove score <= 15
    removed = backend.zremrangebyscore("zkey", 0.0, 15.0)
    assert removed == 1
    assert backend.zcard("zkey") == 2

    # Query range
    members = backend.zrangebyscore("zkey", 15.0, 35.0)
    assert members == ["member2", "member3"]


def test_local_state_backend_sliding_window():
    backend = LocalStateBackend()
    now = time.time()

    # Window of 60s, max 3 requests
    allowed, count, remaining = backend.sliding_window_counter(
        key="test_ratelimit:user1",
        window_seconds=60,
        max_requests=3,
        now_ts=now,
    )
    assert allowed is True
    assert count == 1
    assert remaining == 2

    # 2nd request
    allowed, count, remaining = backend.sliding_window_counter(
        key="test_ratelimit:user1",
        window_seconds=60,
        max_requests=3,
        now_ts=now + 1,
    )
    assert allowed is True
    assert count == 2
    assert remaining == 1

    # 3rd request (at limit)
    allowed, count, remaining = backend.sliding_window_counter(
        key="test_ratelimit:user1",
        window_seconds=60,
        max_requests=3,
        now_ts=now + 2,
    )
    assert allowed is True
    assert count == 3
    assert remaining == 0

    # 4th request (exceeded limit)
    allowed, count, remaining = backend.sliding_window_counter(
        key="test_ratelimit:user1",
        window_seconds=60,
        max_requests=3,
        now_ts=now + 3,
    )
    assert allowed is False
    assert count == 3
    assert remaining == 0


# --- 2. Distributed Lock Tests ---

def test_distributed_lock_acquire_and_release():
    backend = LocalStateBackend()
    lock = DistributedLock(name="resource_a", backend=backend, lease_seconds=10)

    # First acquisition succeeds
    acquired = lock.acquire()
    assert acquired is True
    assert lock.is_held is True
    assert lock.owner_token is not None

    # Second acquisition for same resource fails
    lock2 = DistributedLock(name="resource_a", backend=backend, lease_seconds=10)
    assert lock2.acquire() is False

    # First lock releases
    released = lock.release()
    assert released is True
    assert lock.is_held is False

    # Second lock can now acquire
    assert lock2.acquire() is True
    assert lock2.release() is True


def test_distributed_lock_non_owner_cannot_release():
    backend = LocalStateBackend()
    lock1 = DistributedLock(name="resource_b", backend=backend, lease_seconds=10)
    lock2 = DistributedLock(name="resource_b", backend=backend, lease_seconds=10)

    assert lock1.acquire() is True

    # lock2 attempts to release lock1's hold - must be rejected
    lock2._owner_token = "tampered_token_uuid"
    released = lock2.release()
    assert released is False

    # Resource still held by lock1
    assert lock1.is_held is True
    assert lock1.release() is True


def test_distributed_lock_context_manager():
    backend = LocalStateBackend()
    with DistributedLock(name="resource_c", backend=backend, lease_seconds=5) as lock:
        assert lock.is_held is True
        # Try to acquire concurrently
        contender = DistributedLock(name="resource_c", backend=backend, lease_seconds=5)
        assert contender.acquire() is False

    # Outside block, lock is released
    contender2 = DistributedLock(name="resource_c", backend=backend, lease_seconds=5)
    assert contender2.acquire() is True
    contender2.release()


@pytest.mark.asyncio
async def test_distributed_lock_async_context_manager():
    backend = LocalStateBackend()
    async with DistributedLock(name="async_res", backend=backend, lease_seconds=5) as lock:
        assert lock.is_held is True

    contender = DistributedLock(name="async_res", backend=backend, lease_seconds=5)
    assert contender.acquire() is True
    contender.release()


# --- 3. Idempotency Manager Tests ---

def test_idempotency_first_execution_and_replay():
    backend = LocalStateBackend()
    mgr = IdempotencyManager(backend=backend)

    call_count = 0

    def target_operation():
        nonlocal call_count
        call_count += 1
        return {"status": "SUCCESS", "tx_id": "12345"}

    key = "idem_key_001"
    op = "tool_execution"
    ident = "user_admin"
    ep = "/api/v1/execution/submit"
    payload = {"tool": "google_search", "query": "hello"}

    # 1. First execution executes callback
    res1, cached1 = mgr.execute_idempotent(
        key=key,
        operation=op,
        identity=ident,
        endpoint=ep,
        payload=payload,
        fn=target_operation,
    )
    assert cached1 is False
    assert res1 == {"status": "SUCCESS", "tx_id": "12345"}
    assert call_count == 1

    # 2. Replay with identical payload returns cached result without re-executing
    res2, cached2 = mgr.execute_idempotent(
        key=key,
        operation=op,
        identity=ident,
        endpoint=ep,
        payload=payload,
        fn=target_operation,
    )
    assert cached2 is True
    assert res2 == {"status": "SUCCESS", "tx_id": "12345"}
    assert call_count == 1  # Not executed again!


def test_idempotency_conflict_detection():
    backend = LocalStateBackend()
    mgr = IdempotencyManager(backend=backend)

    key = "idem_key_conflict"
    op = "approval_resolution"
    ident = "admin_user"
    ep = "/api/v1/audit/approvals/app_1/resolve"

    # Execution 1 with payload A
    mgr.execute_idempotent(
        key=key,
        operation=op,
        identity=ident,
        endpoint=ep,
        payload={"verdict": "APPROVED", "notes": "LGTM"},
        fn=lambda: {"result": "ok"},
    )

    # Execution 2 with SAME key but DIFFERENT payload B -> must raise HTTP 409 Conflict
    with pytest.raises(IdempotencyConflictError) as exc_info:
        mgr.execute_idempotent(
            key=key,
            operation=op,
            identity=ident,
            endpoint=ep,
            payload={"verdict": "REJECTED", "notes": "Changed mind"},
            fn=lambda: {"result": "conflict"},
        )

    assert "differing payload" in str(exc_info.value)
    assert exc_info.value.status_code == 409


def test_idempotency_production_fail_closed():
    """In production mode with Redis backend failure, mutations must fail-closed (HTTP 503)."""
    mock_backend = MagicMock()
    mock_backend.get.side_effect = RedisConnectionError("Redis cluster unreachable")

    mgr = IdempotencyManager(backend=mock_backend)

    with patch("app.distributed.idempotency.config") as mock_cfg:
        mock_cfg.ENVIRONMENT = "production"
        with pytest.raises(IdempotencyConflictError) as exc_info:
            mgr.execute_idempotent(
                key="prod_key",
                operation="mutation",
                identity="admin",
                endpoint="/api/v1/mutate",
                payload={"data": 1},
                fn=lambda: {"ok": True},
            )
        assert exc_info.value.status_code == 503


# --- 4. Distributed Rate Limiter Tests ---

def test_distributed_rate_limiter_sliding_window():
    backend = LocalStateBackend()
    limiter = RateLimiter(window_seconds=60, requests_per_minute=2, burst=1, backend=backend)

    # 1st request -> allowed
    is_limited, limit, remaining, retry_after = limiter.is_rate_limited("client_x", "/api/v1/test")
    assert is_limited is False
    assert limit == 2
    assert remaining == 1
    assert retry_after == 0

    # 2nd request -> allowed (limit reached)
    is_limited, limit, remaining, retry_after = limiter.is_rate_limited("client_x", "/api/v1/test")
    assert is_limited is False
    assert remaining == 0

    # 3rd request -> blocked
    is_limited, limit, remaining, retry_after = limiter.is_rate_limited("client_x", "/api/v1/test")
    assert is_limited is True
    assert remaining == 0
    assert retry_after > 0


def test_distributed_rate_limiter_production_fail_closed():
    """When Redis is configured in production and fails, RateLimiter must fail-closed."""
    mock_backend = MagicMock()
    mock_backend.sliding_window_counter.side_effect = RedisConnectionError("Connection lost")

    limiter = RateLimiter(window_seconds=60, requests_per_minute=10, backend=mock_backend)

    with patch("app.core.ratelimit.config") as mock_cfg:
        mock_cfg.ENVIRONMENT = "production"
        mock_cfg.DISTRIBUTED_STATE_ENABLED = True
        mock_cfg.RATE_LIMIT_DISTRIBUTED = True

        with pytest.raises(RedisConnectionError):
            limiter.is_rate_limited("client_fail", "/api/v1/test")
