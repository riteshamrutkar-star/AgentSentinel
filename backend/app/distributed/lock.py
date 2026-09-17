"""
AgentSentinel Phase 0.9: Distributed Mutual Exclusion Locks.
Ensures coordinated atomic execution across multi-instance backend nodes.
Supports lease TTLs, unique ownership tokens, and atomic Lua release.
"""

import time
import uuid
import asyncio
import threading
from typing import Optional, Any

from app.core.config import settings
from app.core.logger import logger
from app.distributed.redis import RedisManager, get_redis_client, RedisConnectionError


class LockError(Exception):
    """Raised when a distributed lock cannot be acquired or fails closed."""
    pass


class DistributedLock:
    """
    Mutual exclusion lock for coordinating critical state transitions across nodes.
    Supports context managers (sync and async), unique ownership tokens, and lease timeouts.
    """

    RELEASE_LUA = """
    if redis.call('GET', KEYS[1]) == ARGV[1] then
        return redis.call('DEL', KEYS[1])
    else
        return 0
    end
    """

    _local_locks: dict = {}
    _local_registry_lock = threading.Lock()

    def __init__(
        self,
        name: str,
        backend: Optional[Any] = None,
        ttl_seconds: int = 15,
        timeout_seconds: float = 0.2,
        lease_seconds: Optional[int] = None,
    ):
        self.name = f"lock:{name}" if not name.startswith("lock:") else name
        self.backend = backend
        self.ttl_seconds = lease_seconds if lease_seconds is not None else ttl_seconds
        self.timeout_seconds = timeout_seconds
        self.owner_token: Optional[str] = None
        self._acquired = False
        self._manager = RedisManager.get_instance()

    @property
    def is_held(self) -> bool:
        return bool(self._acquired)

    @property
    def _owner_token(self) -> Optional[str]:
        return self.owner_token

    @_owner_token.setter
    def _owner_token(self, val: Optional[str]):
        self.owner_token = val
        self._acquired = val is not None

    def _get_local_lock(self) -> threading.Lock:
        with self._local_registry_lock:
            if self.name not in self._local_locks:
                self._local_locks[self.name] = threading.Lock()
            return self._local_locks[self.name]

    def acquire(self) -> bool:
        """Attempts to acquire the lock synchronously up to timeout_seconds."""
        token = str(uuid.uuid4())

        if self.backend is not None:
            deadline = time.time() + self.timeout_seconds
            while True:
                with getattr(self.backend, "_lock", threading.RLock()):
                    existing = self.backend.get(self.name)
                    if existing is None:
                        self.backend.set(self.name, token, expire_seconds=self.ttl_seconds)
                        self.owner_token = token
                        self._acquired = True
                        return True
                if time.time() >= deadline:
                    return False
                time.sleep(0.01)

        client = self._manager.get_client()
        if client is not None:
            # Distributed Redis Lock
            formatted_key = self._manager.format_key(self.name)
            ttl_ms = int(self.ttl_seconds * 1000)
            deadline = time.time() + self.timeout_seconds

            while time.time() <= deadline:
                try:
                    acquired = bool(client.set(formatted_key, token, nx=True, px=ttl_ms))
                    if acquired:
                        self.owner_token = token
                        self._acquired = True
                        return True
                except Exception as e:
                    logger.error(f"Redis lock error on {self.name}: {e}")
                    if settings.is_production:
                        raise LockError(f"Fail-closed: Distributed lock '{self.name}' unavailable in production.")
                    break
                time.sleep(0.05)

            if settings.is_production and (settings.DISTRIBUTED_STATE_ENABLED or settings.RATE_LIMIT_DISTRIBUTED):
                raise LockError(f"Failed to acquire distributed lock '{self.name}' before timeout ({self.timeout_seconds}s).")
            return False
        else:
            if settings.is_production and (settings.DISTRIBUTED_STATE_ENABLED or settings.RATE_LIMIT_DISTRIBUTED):
                raise LockError(f"Fail-closed: Redis lock required in production but unavailable for '{self.name}'.")

            # Local fallback lock
            local_lock = self._get_local_lock()
            acquired = local_lock.acquire(timeout=self.timeout_seconds)
            if acquired:
                self.owner_token = token
                self._acquired = True
                return True
            return False

    def release(self) -> bool:
        """Releases the lock only if owned by this instance's token."""
        if not self._acquired or not self.owner_token:
            return False

        if self.backend is not None:
            with getattr(self.backend, "_lock", threading.RLock()):
                existing = self.backend.get(self.name)
                if existing == self.owner_token:
                    self.backend.delete(self.name)
                    self._acquired = False
                    self.owner_token = None
                    return True
                return False

        client = self._manager.get_client()
        if client is not None:
            formatted_key = self._manager.format_key(self.name)
            try:
                result = client.eval(self.RELEASE_LUA, 1, formatted_key, self.owner_token)
                released = bool(result)
            except Exception as e:
                logger.error(f"Error releasing Redis lock {self.name}: {e}")
                released = False
        else:
            local_lock = self._get_local_lock()
            try:
                local_lock.release()
                released = True
            except RuntimeError:
                released = False

        self._acquired = False
        self.owner_token = None
        return released

    def __enter__(self):
        if not self.acquire():
            raise LockError(f"Could not acquire lock '{self.name}' within {self.timeout_seconds}s timeout.")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()

    async def __aenter__(self):
        if not self.acquire():
            raise LockError(f"Could not acquire async lock '{self.name}' within {self.timeout_seconds}s timeout.")
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.release()
