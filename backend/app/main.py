from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.core.config import settings
from app.core.logger import logger
from app.api.routes import router as api_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler for application startup and shutdown."""
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION} ({settings.ENVIRONMENT})")
    try:
        from app.db.base import Base
        from app.db.session import engine
        Base.metadata.create_all(bind=engine)
    except Exception as e:
        logger.warning(f"Could not auto-create tables during lifespan: {e}")
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

    # Enable CORS for dashboard frontend with restricted, configurable origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
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
