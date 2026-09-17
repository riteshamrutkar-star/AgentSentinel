"""
AgentSentinel Phase 0.9: Centralized Redis Connection & Health Management.
Provides managed, resilient Redis connection pooling, health checks, key prefixing,
and fail-closed safety semantics for distributed deployments.
"""

import threading
from typing import Optional
from urllib.parse import urlparse

try:
    import redis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False

from app.core.config import settings
from app.core.logger import logger


class RedisConnectionError(Exception):
    """Raised when distributed Redis operations fail and fail-closed is required."""
    pass


class RedisManager:
    """
    Thread-safe connection manager for Redis.
    Provides connection pooling, prefixing, and health checks.
    """

    _instance: Optional["RedisManager"] = None
    _lock = threading.Lock()

    def __init__(self):
        self._client: Optional["redis.Redis"] = None
        self._pool: Optional["redis.ConnectionPool"] = None
        self._initialized = False

    @classmethod
    def get_instance(cls) -> "RedisManager":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    @property
    def prefix(self) -> str:
        return settings.REDIS_PREFIX

    def format_key(self, key: str) -> str:
        """Prefaces raw key with configured application prefix."""
        if key.startswith(self.prefix):
            return key
        return f"{self.prefix}{key}"

    def get_client(self) -> Optional["redis.Redis"]:
        """Returns initialized Redis client, or None if Redis is disabled/unavailable."""
        if not HAS_REDIS:
            logger.warning("Redis Python package is not installed.")
            return None

        if not settings.DISTRIBUTED_STATE_ENABLED and not settings.RATE_LIMIT_DISTRIBUTED:
            return None

        with self._lock:
            if self._client is None:
                try:
                    if settings.REDIS_URL:
                        self._pool = redis.ConnectionPool.from_url(
                            settings.REDIS_URL,
                            socket_connect_timeout=settings.REDIS_CONNECT_TIMEOUT,
                            socket_timeout=settings.REDIS_SOCKET_TIMEOUT,
                            decode_responses=True,
                            max_connections=20,
                        )
                    else:
                        self._pool = redis.ConnectionPool(
                            host=settings.REDIS_HOST,
                            port=settings.REDIS_PORT,
                            password=settings.REDIS_PASSWORD,
                            db=settings.REDIS_DB,
                            socket_connect_timeout=settings.REDIS_CONNECT_TIMEOUT,
                            socket_timeout=settings.REDIS_SOCKET_TIMEOUT,
                            decode_responses=True,
                            max_connections=20,
                        )
                    self._client = redis.Redis(connection_pool=self._pool)
                    # Test connection with ping
                    self._client.ping()
                    self._initialized = True
                    logger.info(f"Successfully connected to Redis at {self._get_safe_connection_summary()}")
                except Exception as e:
                    self._client = None
                    self._pool = None
                    self._initialized = False
                    logger.warning(f"Failed to connect to Redis: {e}")
                    if settings.is_production and (settings.DISTRIBUTED_STATE_ENABLED or settings.RATE_LIMIT_DISTRIBUTED):
                        raise RedisConnectionError(f"Fail-closed production requirement: Unable to connect to Redis: {e}")
                    return None

            return self._client

    def ping(self) -> bool:
        """Health check probe for Redis connectivity."""
        if not HAS_REDIS:
            return False
        try:
            client = self.get_client()
            if client is None:
                return False
            return bool(client.ping())
        except Exception as e:
            logger.debug(f"Redis ping failed: {e}")
            return False

    def close(self) -> None:
        """Closes all pool connections."""
        with self._lock:
            if self._client is not None:
                try:
                    self._client.close()
                except Exception:
                    pass
                self._client = None
            if self._pool is not None:
                try:
                    self._pool.disconnect()
                except Exception:
                    pass
                self._pool = None
            self._initialized = False

    def _get_safe_connection_summary(self) -> str:
        if settings.REDIS_URL:
            parsed = urlparse(settings.REDIS_URL)
            host = parsed.hostname or "unknown"
            port = parsed.port or 6379
            return f"{host}:{port} (URL configured)"
        return f"{settings.REDIS_HOST}:{settings.REDIS_PORT}/db{settings.REDIS_DB}"


def get_redis_client() -> Optional["redis.Redis"]:
    """Helper function to retrieve active Redis client."""
    return RedisManager.get_instance().get_client()
