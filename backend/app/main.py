from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.core.config import settings
from app.core.logger import logger
from app.api.routes import router as api_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler for application startup and shutdown."""
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION} ({settings.ENVIRONMENT})")
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
