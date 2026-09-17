"""
AgentSentinel Phase 0.9: Unified Rate Limiter & Sliding-Window Engine.
Supports both process-local in-memory tracking (for dev/test single worker)
and atomic horizontally distributed tracking backed by Redis.

ARCHITECTURAL BEHAVIOR:
- Single-instance / dev / test: Uses LocalStateBackend (process-local sliding window).
- Multi-instance / cluster production: Uses RedisStateBackend (atomic Redis Lua script).
- Fail-closed in production: If Redis is required and unreachable in production mode,
  requests are rejected (fail-closed) rather than silently downgraded.
"""

import time
import threading
from typing import Dict, List, Tuple, Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from starlette.types import ASGIApp

from app.core.config import settings
from app.core.logger import logger
from app.distributed.state import (
    DistributedStateBackend,
    LocalStateBackend,
    get_state_backend,
)
from app.distributed.redis import RedisConnectionError

config = settings


class RateLimiter:
    """
    Unified sliding-window rate limiter.
    Delegates atomic window counter evaluation to a DistributedStateBackend.
    """

    def __init__(
        self,
        window_seconds: int = 60,
        requests_per_minute: Optional[int] = None,
        burst: Optional[int] = None,
        backend: Optional[DistributedStateBackend] = None,
    ):
        self.window_seconds = window_seconds
        self.requests_per_minute = requests_per_minute
        self.burst = burst
        self._backend = backend

    @property
    def backend(self) -> DistributedStateBackend:
        if self._backend is None:
            self._backend = get_state_backend()
        return self._backend

    @property
    def is_distributed(self) -> bool:
        return self.backend.is_distributed

    @classmethod
    def get_architecture_notice(cls) -> str:
        return (
            "ARCHITECTURAL NOTICE: AgentSentinel Rate Limiter supports dual modes: "
            "LocalStateBackend for single-instance development (which is NOT a globally coordinated distributed rate limiter) "
            "and RedisStateBackend for horizontally coordinated multi-replica production deployments."
        )

    def check_rate_limit(self, client_id: str, endpoint_path: str = "/api/v1/test") -> Tuple[bool, int, int]:
        """Convenience method returning (allowed, remaining, retry_after)."""
        is_limited, limit, remaining, retry_after = self.is_rate_limited(client_id, endpoint_path)
        return not is_limited, remaining, retry_after

    def is_rate_limited(self, client_id: str, endpoint_path: str) -> Tuple[bool, int, int, int]:
        """
        Determines whether the client has exceeded the rate limit for the given endpoint.
        Returns: (is_limited, limit, remaining, retry_after_seconds)
        """
        if self._backend is None and (settings.TESTING or not settings.RATE_LIMIT_ENABLED):
            return False, 10000, 10000, 0

        if type(self) is InMemoryRateLimiter and self.burst is not None:
            limit = self.burst
            category = "burst"
        elif self.requests_per_minute is not None:
            limit = self.requests_per_minute
            category = "custom"
        else:
            category, limit = self._resolve_limit(endpoint_path)
            if self.burst is not None:
                limit = self.burst

        rate_key = f"ratelimit:{client_id}:{category}"

        env = getattr(config, "ENVIRONMENT", getattr(settings, "ENVIRONMENT", "development"))
        is_prod = env == "production"

        try:
            if hasattr(self.backend, "sliding_window_counter") and callable(getattr(self.backend, "sliding_window_counter")):
                allowed, count, remaining = self.backend.sliding_window_counter(
                    key=rate_key,
                    window_seconds=self.window_seconds,
                    max_requests=limit,
                )
                is_limited = not allowed
                retry_after = self.window_seconds if is_limited else 0
                return is_limited, limit, remaining, retry_after
            else:
                return self.backend.check_sliding_window(
                    key=rate_key,
                    limit=limit,
                    window_seconds=self.window_seconds,
                )
        except RedisConnectionError as rce:
            logger.critical(f"Fail-closed rate limiting enforced: {rce}")
            if is_prod:
                raise rce
            return True, limit, 0, 60
        except Exception as e:
            logger.error(f"Rate limiting backend error on '{endpoint_path}': {e}")
            if is_prod:
                raise e
            # Dev fallback
            return False, limit, limit, 0

    def _resolve_limit(self, path: str) -> Tuple[str, int]:
        """Maps endpoint paths to category quotas."""
        if path.startswith("/api/v1/admin/keys"):
            return "admin_keys", 20
        elif path.startswith("/api/v1/intercept"):
            return "intercept", 1200
        elif path.startswith("/api/v1/audit/approvals"):
            return "approvals", 120
        elif path.startswith("/api/v1/attack"):
            return "attack_simulation", 60
        elif path.startswith("/api/v1/research"):
            return "research_experiment", 30
        elif path.startswith("/health") or path.startswith("/metrics") or path in ("/", "/docs", "/openapi.json"):
            return "public_health", 5000
        return "general_api", 600

    def reset(self) -> None:
        """Clears all stored rate limit history."""
        try:
            self.backend.clear()
        except Exception as e:
            logger.warning(f"Error resetting rate limiter backend: {e}")


class InMemoryRateLimiter(RateLimiter):
    """
    Backwards-compatible in-memory rate limiter for single-worker tests.
    Explicitly forces LocalStateBackend.
    """

    def __init__(
        self,
        window_seconds: int = 60,
        requests_per_minute: Optional[int] = None,
        burst: Optional[int] = None,
    ):
        super().__init__(
            window_seconds=window_seconds,
            requests_per_minute=requests_per_minute,
            burst=burst,
            backend=LocalStateBackend(),
        )


class DistributedRateLimiter(RateLimiter):
    """
    Production distributed rate limiter utilizing the globally configured state backend.
    """
    pass


# Global singleton rate limiter instance
global_rate_limiter = DistributedRateLimiter()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """FastAPI/Starlette middleware enforcing endpoint rate limiting."""

    def __init__(self, app: ASGIApp, limiter: Optional[RateLimiter] = None):
        super().__init__(app)
        self.limiter = limiter or global_rate_limiter

    async def dispatch(self, request: Request, call_next) -> Response:
        # Resolve client identifier: API key header or client IP
        client_ip = request.client.host if request.client else "unknown_client"
        client_key = request.headers.get("X-API-Key") or client_ip

        is_limited, limit, remaining, retry_after = self.limiter.is_rate_limited(
            client_id=client_key, endpoint_path=request.url.path
        )

        if is_limited:
            logger.warning(
                f"Rate limit exceeded on '{request.url.path}' by client '{client_ip}'. "
                f"Quota: {limit}/min. Retry-After: {retry_after}s."
            )
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Too Many Requests: Rate limit quota exceeded. Please slow down.",
                    "limit_per_minute": limit,
                    "retry_after_seconds": retry_after,
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(retry_after),
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response