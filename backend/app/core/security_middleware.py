"""
AgentSentinel Phase 0.8: Security Headers, Request ID & Payload Limit Middleware.
Hardens the HTTP API perimeter and ensures end-to-end request traceability.
"""

import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from starlette.types import ASGIApp

from app.core.config import settings
from app.core.logger import logger


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Injects defensive HTTP security headers on all API responses."""

    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
        response.headers["Content-Security-Policy"] = "default-src 'self'"

        # Emit HSTS only when request is over HTTPS or environment is production.
        # Do not force HSTS into ordinary local HTTP development.
        is_https = request.url.scheme == "https" or request.headers.get("x-forwarded-proto", "").lower() == "https"
        if is_https or settings.is_production:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response


class RequestIdMiddleware(BaseHTTPMiddleware):
    """
    Assigns or propagates unique request and correlation IDs.
    Enables distributed tracing across log entries and security audit events.
    """

    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next) -> Response:
        req_id = request.headers.get("X-Request-ID") or f"req_{uuid.uuid4().hex[:12]}"
        corr_id = request.headers.get("X-Correlation-ID") or req_id

        request.state.request_id = req_id
        request.state.correlation_id = corr_id

        response = await call_next(request)

        response.headers["X-Request-ID"] = req_id
        response.headers["X-Correlation-ID"] = corr_id
        return response


class PayloadSizeLimitMiddleware(BaseHTTPMiddleware):
    """Protects against memory exhaustion denial of service by rejecting payloads exceeding limit."""

    def __init__(self, app: ASGIApp, max_bytes: int = 10 * 1024 * 1024, max_size_bytes: int = None):
        super().__init__(app)
        self.max_bytes = max_size_bytes if max_size_bytes is not None else max_bytes

    async def dispatch(self, request: Request, call_next) -> Response:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                length = int(content_length)
                if length > self.max_bytes:
                    logger.warning(f"Payload limit exceeded: {length} bytes > {self.max_bytes} bytes allowed.")
                    return JSONResponse(
                        status_code=413,
                        content={
                            "detail": f"Payload Too Large: Request body ({length} bytes) exceeds maximum limit ({self.max_bytes} bytes).",
                        },
                    )
            except ValueError:
                pass

        return await call_next(request)