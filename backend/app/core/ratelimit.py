"""
AgentSentinel Phase 0.8: In-Memory Sliding-Window Rate Limiter.

ARCHITECTURAL NOTICE:
This rate limiter is implemented as an in-memory, thread-safe sliding window
appropriate for the current single-worker deployment model.
It is process-local and NOT a globally coordinated distributed rate limiter:
- Single-worker instance = effective instance-local limiter (recommended for Phase 0.8)
- Multiple workers in one container = separate limiter state per worker process
- Multiple container replicas = separate limiter state per replica
- Distributed cluster-wide rate limiting requires a shared state backend (e.g. Redis)
  in a future phase.
"""

import time
import threading
from collections import defaultdict
from typing import Dict, List, Tuple, Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from starlette.types import ASGIApp

from app.core.config import settings
from app.core.logger import logger


class InMemoryRateLimiter:
    """
    Thread-safe in-memory sliding-window token counter.
    Tracks request timestamps within a 60-second window per (client_key, endpoint_category).
    """

    def __init__(
        self,
        window_seconds: int = 60,
        requests_per_minute: Optional[int] = None,
        burst: Optional[int] = None,
    ):
        self.window_seconds = window_seconds
        self.requests_per_minute = requests_per_minute
        self.burst = burst
        self._lock = threading.Lock()
        # Map: category_key -> list of timestamp floats
        self._history: Dict[str, List[float]] = defaultdict(list)

    @property
    def is_distributed(self) -> bool:
        return False

    @classmethod
    def get_architecture_notice(cls) -> str:
        return (
            "ARCHITECTURAL NOTICE: This rate limiter is implemented as an in-memory, "
            "thread-safe sliding window appropriate for single-instance deployments. "
            "It is NOT a globally coordinated distributed rate limiter."
        )

    def check_rate_limit(self, client_id: str, endpoint_path: str = "/api/v1/test") -> Tuple[bool, int, int]:
        """Convenience method returning (allowed, remaining, retry_after)."""
        category, limit = self._resolve_limit(endpoint_path)
        if self.burst is not None:
            limit = self.burst

        key = f"{client_id}:{category}"
        now = time.time()
        window_start = now - self.window_seconds

        with self._lock:
            timestamps = [t for t in self._history[key] if t > window_start]
            count = len(timestamps)

            if count >= limit:
                oldest = timestamps[0]
                retry_after = max(1, int(self.window_seconds - (now - oldest)))
                self._history[key] = timestamps
                return False, 0, retry_after

            timestamps.append(now)
            self._history[key] = timestamps
            remaining = max(0, limit - len(timestamps))
            return True, remaining, 0

    def is_rate_limited(self, client_id: str, endpoint_path: str) -> Tuple[bool, int, int, int]:
        """
        Determines whether the client has exceeded the rate limit for the given endpoint.
        Returns: (is_limited, limit, remaining, retry_after_seconds)
        """
        if settings.TESTING or not settings.RATE_LIMIT_ENABLED:
            return False, 10000, 10000, 0

        category, limit = self._resolve_limit(endpoint_path)
        key = f"{client_id}:{category}"
        now = time.time()
        window_start = now - self.window_seconds

        with self._lock:
            # Purge timestamps older than sliding window
            timestamps = [t for t in self._history[key] if t > window_start]
            count = len(timestamps)

            if count >= limit:
                # Oldest timestamp in window determines retry delay
                oldest = timestamps[0]
                retry_after = max(1, int(self.window_seconds - (now - oldest)))
                self._history[key] = timestamps
                return True, limit, 0, retry_after

            timestamps.append(now)
            self._history[key] = timestamps
            remaining = max(0, limit - len(timestamps))
            return False, limit, remaining, 0

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
        """Clears all stored rate limit history (useful for testing)."""
        with self._lock:
            self._history.clear()


global_rate_limiter = InMemoryRateLimiter()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """FastAPI/Starlette middleware enforcing endpoint rate limiting."""

    def __init__(self, app: ASGIApp, limiter: Optional[InMemoryRateLimiter] = None):
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