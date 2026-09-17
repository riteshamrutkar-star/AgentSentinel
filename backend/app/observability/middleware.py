"""
AgentSentinel Phase 0.8: Observability Timing & Metrics Middleware.
Records HTTP request duration and increment counts for all endpoints.
"""

import time
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from app.observability.metrics import metrics_registry


class MetricsMiddleware(BaseHTTPMiddleware):
    """Tracks request counts and latency distributions in Prometheus metrics."""

    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next) -> Response:
        start_time = time.perf_counter()
        response = await call_next(request)
        duration = time.perf_counter() - start_time

        path = request.url.path
        method = request.method
        status_code = str(response.status_code)

        metrics_registry.http_requests_total.inc(
            endpoint=path,
            method=method,
            status=status_code,
        )
        metrics_registry.http_request_duration_seconds.observe(
            duration,
            endpoint=path,
            method=method,
        )

        return response