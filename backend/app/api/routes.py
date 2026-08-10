from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.config import settings
from app.db.session import get_db
from app.db.crud import list_security_events, save_security_event
from app.events.examples import get_benign_event_example, get_suspicious_event_example
from app.api.intercept import router as intercept_router
from app.api.audit import router as audit_router
from app.api.anomaly import router as anomaly_router

router = APIRouter()

# Include Phase 4/5 Interceptor & Policy Router
router.include_router(intercept_router)

# Include Phase 6 Audit & Approval Router
router.include_router(audit_router)

# Include Phase 7 Behavioral Anomaly Router
router.include_router(anomaly_router)

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

@router.get("/api/v1/events/db-test", tags=["Database"])
async def test_db_persistence(db: Session = Depends(get_db)):
    """Saves a sample security event to the database and retrieves all logged events."""
    sample_event = get_suspicious_event_example()
    save_security_event(db, sample_event)
    events = list_security_events(db, limit=10)
    return {
        "status": "success",
        "message": "Database event persistence test passed",
        "total_events_in_db": len(events),
        "latest_event_id": events[0].event_id if events else None,
        "latest_event_tool": events[0].tool_name if events else None,
    }
