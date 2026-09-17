"""
AgentSentinel Phase 0.9: Distributed State Abstraction.
Provides a unified state interface with two concrete backends:
1. LocalStateBackend: In-memory, thread-safe implementation for single-worker dev/test.
2. RedisStateBackend: Distributed, atomic Redis-backed implementation for multi-worker/multi-instance deployments.
"""

import time
import uuid
import threading
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import settings
from app.core.logger import logger
from app.distributed.redis import RedisManager, RedisConnectionError, get_redis_client


class DistributedStateBackend(ABC):
    """Abstract base class for state storage backends."""

    @property
    @abstractmethod
    def is_distributed(self) -> bool:
        """Returns True if the backend is horizontally shared across cluster nodes."""
        pass

    @abstractmethod
    def get(self, key: str) -> Optional[str]:
        """Retrieves a string value by key."""
        pass

    @abstractmethod
    def set(self, key: str, value: str, expire_seconds: Optional[int] = None) -> bool:
        """Sets a string value by key with optional TTL."""
        pass

    @abstractmethod
    def delete(self, key: str) -> bool:
        """Deletes a key."""
        pass

    @abstractmethod
    def exists(self, key: str) -> bool:
        """Checks if a key exists."""
        pass

    @abstractmethod
    def incr(self, key: str) -> int:
        """Atomically increments an integer counter."""
        pass

    @abstractmethod
    def expire(self, key: str, seconds: int) -> bool:
        """Sets a TTL in seconds on a key."""
        pass

    @abstractmethod
    def check_sliding_window(
        self,
        key: str,
        limit: int,
        window_seconds: int,
        now: Optional[float] = None,
    ) -> Tuple[bool, int, int, int]:
        """
        Atomically evaluates and records an event in a sliding-window rate limit.
        Returns: (is_limited, limit, remaining, retry_after)
        """
        pass

    @abstractmethod
    def clear(self) -> None:
        """Clears stored state (intended for testing)."""
        pass


class LocalStateBackend(DistributedStateBackend):
    """
    Thread-safe, process-local state backend.
    Used in development, testing, and single-worker instances.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._store: Dict[str, str] = {}
        self._ttls: Dict[str, float] = {}
        # Sorted sets: key -> dict of {member: score}
        self._sorted_sets: Dict[str, Dict[str, float]] = defaultdict(dict)
        self._zset_ttls: Dict[str, float] = {}

    @property
    def is_distributed(self) -> bool:
        return False

    def _purge_expired(self, key: str) -> None:
        now = time.time()
        if key in self._ttls and self._ttls[key] <= now:
            self._store.pop(key, None)
            self._ttls.pop(key, None)
        if key in self._zset_ttls and self._zset_ttls[key] <= now:
            self._sorted_sets.pop(key, None)
            self._zset_ttls.pop(key, None)

    def get(self, key: str) -> Optional[str]:
        with self._lock:
            self._purge_expired(key)
            return self._store.get(key)

    def set(self, key: str, value: str, expire_seconds: Optional[int] = None) -> bool:
        with self._lock:
            self._store[key] = str(value)
            if expire_seconds is not None:
                self._ttls[key] = time.time() + expire_seconds
            else:
                self._ttls.pop(key, None)
            return True

    def delete(self, key: str) -> bool:
        with self._lock:
            existed = (key in self._store) or (key in self._sorted_sets)
            self._store.pop(key, None)
            self._ttls.pop(key, None)
            self._sorted_sets.pop(key, None)
            self._zset_ttls.pop(key, None)
            return existed

    def exists(self, key: str) -> bool:
        with self._lock:
            self._purge_expired(key)
            return (key in self._store) or (key in self._sorted_sets)

    def incr(self, key: str) -> int:
        with self._lock:
            self._purge_expired(key)
            val = int(self._store.get(key, 0)) + 1
            self._store[key] = str(val)
            return val

    def expire(self, key: str, seconds: int) -> bool:
        with self._lock:
            self._purge_expired(key)
            if key in self._store or key in self._sorted_sets:
                exp = time.time() + seconds
                if key in self._store:
                    self._ttls[key] = exp
                if key in self._sorted_sets:
                    self._zset_ttls[key] = exp
                return True
            return False

    def check_sliding_window(
        self,
        key: str,
        limit: int,
        window_seconds: int,
        now: Optional[float] = None,
    ) -> Tuple[bool, int, int, int]:
        """Sliding-window evaluation with thread safety."""
        current_time = now if now is not None else time.time()
        window_start = current_time - window_seconds

        with self._lock:
            zset = self._sorted_sets[key]
            # Remove entries older than window_start
            expired = [m for m, score in zset.items() if score <= window_start]
            for m in expired:
                del zset[m]

            current_count = len(zset)
            if current_count >= limit:
                # Find oldest timestamp in window
                oldest_ts = min(zset.values()) if zset else current_time
                retry_after = max(1, int(window_seconds - (current_time - oldest_ts)))
                return True, limit, 0, retry_after

            # Record this event
            entry_id = f"{current_time}_{uuid.uuid4().hex[:6]}"
            zset[entry_id] = current_time
            self._zset_ttls[key] = current_time + window_seconds + 5
            remaining = max(0, limit - len(zset))
            return False, limit, remaining, 0

    def zadd(self, key: str, score: float, member: str) -> int:
        with self._lock:
            self._purge_expired(key)
            is_new = str(member) not in self._sorted_sets[key]
            self._sorted_sets[key][str(member)] = float(score)
            return 1 if is_new else 0

    def zcard(self, key: str) -> int:
        with self._lock:
            self._purge_expired(key)
            return len(self._sorted_sets.get(key, {}))

    def zremrangebyscore(self, key: str, min_score: float, max_score: float) -> int:
        with self._lock:
            self._purge_expired(key)
            zset = self._sorted_sets.get(key, {})
            to_remove = [m for m, s in zset.items() if min_score <= s <= max_score]
            for m in to_remove:
                del zset[m]
            return len(to_remove)

    def zrangebyscore(self, key: str, min_score: float, max_score: float) -> List[str]:
        with self._lock:
            self._purge_expired(key)
            zset = self._sorted_sets.get(key, {})
            items = [(m, s) for m, s in zset.items() if min_score <= s <= max_score]
            items.sort(key=lambda x: x[1])
            return [m for m, s in items]

    def sliding_window_counter(
        self,
        key: str,
        window_seconds: int,
        max_requests: int,
        now_ts: Optional[float] = None,
    ) -> Tuple[bool, int, int]:
        current_time = now_ts if now_ts is not None else time.time()
        window_start = current_time - window_seconds
        with self._lock:
            zset = self._sorted_sets[key]
            expired = [m for m, s in zset.items() if s <= window_start]
            for m in expired:
                del zset[m]
            count = len(zset)
            if count >= max_requests:
                return False, count, 0
            entry_id = f"{current_time}_{uuid.uuid4().hex[:6]}"
            zset[entry_id] = current_time
            count += 1
            remaining = max(0, max_requests - count)
            return True, count, remaining

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self._ttls.clear()
            self._sorted_sets.clear()
            self._zset_ttls.clear()


SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window_seconds = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local member = ARGV[4]
local window_start = now - window_seconds

-- 1. Evict entries outside the sliding window
redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

-- 2. Count active events in window
local current_count = redis.call('ZCARD', key)

if current_count >= limit then
    local oldest = redis.call('ZRANGEBYSCORE', key, window_start, '+inf', 'LIMIT', 0, 1)
    local retry_after = 1
    if #oldest > 0 then
        local oldest_ts = tonumber(redis.call('ZSCORE', key, oldest[1]) or now)
        retry_after = math.max(1, math.floor(window_seconds - (now - oldest_ts)))
    end
    return {1, limit, 0, retry_after}
else
    redis.call('ZADD', key, now, member)
    redis.call('EXPIRE', key, window_seconds + 5)
    local remaining = math.max(0, limit - (current_count + 1))
    return {0, limit, remaining, 0}
end
"""


class RedisStateBackend(DistributedStateBackend):
    """
    Production-grade atomic Redis state backend.
    Enforces atomic sliding-window rate limiting, distributed locking, and fail-closed security.
    """

    def __init__(self):
        self._manager = RedisManager.get_instance()
        self._script_sha: Optional[str] = None
        self._lock = threading.Lock()

    @property
    def is_distributed(self) -> bool:
        return True

    def _get_client(self):
        client = self._manager.get_client()
        if client is None:
            if settings.is_production and (settings.DISTRIBUTED_STATE_ENABLED or settings.RATE_LIMIT_DISTRIBUTED):
                raise RedisConnectionError("Redis client is unavailable in production fail-closed configuration.")
            raise RuntimeError("Redis client is unavailable.")
        return client

    def _format_key(self, key: str) -> str:
        return self._manager.format_key(key)

    def get(self, key: str) -> Optional[str]:
        client = self._get_client()
        return client.get(self._format_key(key))

    def set(self, key: str, value: str, expire_seconds: Optional[int] = None) -> bool:
        client = self._get_client()
        formatted_key = self._format_key(key)
        if expire_seconds is not None:
            return bool(client.set(formatted_key, str(value), ex=expire_seconds))
        return bool(client.set(formatted_key, str(value)))

    def delete(self, key: str) -> bool:
        client = self._get_client()
        return bool(client.delete(self._format_key(key)))

    def exists(self, key: str) -> bool:
        client = self._get_client()
        return bool(client.exists(self._format_key(key)))

    def incr(self, key: str) -> int:
        client = self._get_client()
        return int(client.incr(self._format_key(key)))

    def expire(self, key: str, seconds: int) -> bool:
        client = self._get_client()
        return bool(client.expire(self._format_key(key), seconds))

    def check_sliding_window(
        self,
        key: str,
        limit: int,
        window_seconds: int,
        now: Optional[float] = None,
    ) -> Tuple[bool, int, int, int]:
        client = self._get_client()
        current_time = now if now is not None else time.time()
        member = f"{current_time}_{uuid.uuid4().hex[:6]}"
        formatted_key = self._format_key(key)

        try:
            res = client.eval(
                SLIDING_WINDOW_LUA,
                1,
                formatted_key,
                limit,
                window_seconds,
                current_time,
                member,
            )
            # res format: [is_limited (0/1), limit, remaining, retry_after]
            is_limited = bool(res[0])
            res_limit = int(res[1])
            remaining = int(res[2])
            retry_after = int(res[3])
            return is_limited, res_limit, remaining, retry_after
        except Exception as e:
            logger.error(f"Error executing Redis sliding-window Lua script: {e}")
            if settings.is_production:
                # FAIL-CLOSED: reject request if Redis fails in production
                return True, limit, 0, 60
            raise

    def clear(self) -> None:
        client = self._get_client()
        pattern = f"{self._manager.prefix}*"
        cursor = 0
        while True:
            cursor, keys = client.scan(cursor=cursor, match=pattern, count=100)
            if keys:
                client.delete(*keys)
            if cursor == 0:
                break


# Global backend instances
_local_backend = LocalStateBackend()
_redis_backend: Optional[RedisStateBackend] = None
_backend_lock = threading.Lock()


def get_state_backend() -> DistributedStateBackend:
    """
    Factory resolving active state backend according to environment and configuration.
    Fails closed in production if distributed state is enabled but Redis is unreachable.
    """
    global _redis_backend

    if settings.DISTRIBUTED_STATE_ENABLED or settings.RATE_LIMIT_DISTRIBUTED:
        try:
            with _backend_lock:
                if _redis_backend is None:
                    _redis_backend = RedisStateBackend()
                # Verify client connectivity
                _redis_backend._get_client()
                return _redis_backend
        except Exception as e:
            if settings.is_production:
                logger.critical(f"FAIL-CLOSED: Distributed state backend required in production but Redis failed: {e}")
                raise RedisConnectionError(f"Distributed state backend unavailable: {e}")
            logger.warning(f"Redis backend unavailable ({e}); falling back to LocalStateBackend for dev/test.")
            return _local_backend

    return _local_backend
