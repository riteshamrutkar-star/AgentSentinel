from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.core.config import settings
from app.core.logger import logger
from app.api.routes import router as api_router

from app.core.security_middleware import (
    SecurityHeadersMiddleware,
    RequestIdMiddleware,
    PayloadSizeLimitMiddleware,
)
from app.core.ratelimit import RateLimitMiddleware
from app.observability.middleware import MetricsMiddleware

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler for application startup and shutdown."""
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION} ({settings.ENVIRONMENT})")
    
    # 1. Enforce fail-closed production readiness check
    settings.validate_production_configuration()

    # 2. Apply non-destructive database migrations
    try:
        from app.db.session import engine
        from app.db.migrations import apply_migrations
        applied = apply_migrations(engine)
        logger.info(f"Database schema verified: {applied} new migration(s) applied.")
    except Exception as e:
        logger.warning(f"Database migration verification notice during lifespan: {e}")

    yield
    logger.info(f"Shutting down {settings.APP_NAME}")

def create_app() -> FastAPI:
    """Application factory for initializing the FastAPI app."""
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="Runtime security layer for AI agent tool call interception and auditing.",
        lifespan=lifespan
    )

    # 1. Security Headers Middleware (defense against MIME sniffing, clickjacking)
    app.add_middleware(SecurityHeadersMiddleware)

    # 2. Request ID & Correlation ID Tracing Middleware
    app.add_middleware(RequestIdMiddleware)

    # 3. Payload Size Limiting Middleware (DoS prevention)
    app.add_middleware(PayloadSizeLimitMiddleware, max_bytes=settings.MAX_REQUEST_SIZE_BYTES)

    # 4. In-Memory Sliding-Window Rate Limiting Middleware
    app.add_middleware(RateLimitMiddleware)

    # 5. Prometheus Observability Metrics Middleware
    app.add_middleware(MetricsMiddleware)

    # 6. Enable CORS for dashboard frontend with restricted, configurable origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Request-ID", "X-Correlation-ID"],
    )

    # Global exception handler to mask internal error details from API responses
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error(f"Unhandled exception during {request.method} {request.url.path}: {exc}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "An internal server error occurred while processing the security request.",
                "path": request.url.path,
            }
        )

    # Register API routes
    app.include_router(api_router)

    @app.get("/", tags=["Root"])
    async def root():
        return {
            "message": f"Welcome to {settings.APP_NAME} v{settings.APP_VERSION}",
            "docs": "/docs",
            "health": "/health"
        }

    return app

app = create_app()
