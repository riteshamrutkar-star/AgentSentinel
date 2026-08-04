from fastapi import APIRouter
from app.core.config import settings
from app.events.examples import get_benign_event_example, get_suspicious_event_example

router = APIRouter()

@router.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint to verify backend operational status."""
    return {
        "status": "ok",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT
    }

@router.get("/api/v1/events/benign", tags=["Security Events"])
async def get_benign_event():
    """Returns an example benign tool action security event."""
    event = get_benign_event_example()
    return event.to_dict()

@router.get("/api/v1/events/suspicious", tags=["Security Events"])
async def get_suspicious_event():
    """Returns an example suspicious / unauthorized tool action security event."""
    event = get_suspicious_event_example()
    return event.to_dict()
