"""
AgentSentinel Phase 0.8: Multi-Stage Health, Liveness & Readiness Probes.
Distinguishes fast process liveness from deep dependency readiness and dependency breakdown.
"""

import time
from datetime import datetime, timezone
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logger import logger
from app.db.session import get_db
from app.observability.metrics import metrics_registry
from app.policy.engine import default_policy_engine
from app.execution.registry import default_tool_registry

router = APIRouter(tags=["Health & Operational Probes"])


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@router.get("/health/live", summary="Liveness probe: verifies process is responsive")
def liveness_probe():
    """Lightweight probe verifying application server process is running."""
    return {
        "status": "alive",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "timestamp": utc_now(),
    }


@router.get("/health/ready", summary="Readiness probe: verifies all critical dependencies are operational")
def readiness_probe(db: Session = Depends(get_db)):
    """
    Readiness probe verifying database connectivity, policy engine, and execution gateway.
    Returns HTTP 200 when ready to accept traffic, or HTTP 503 if a dependency is failing.
    """
    is_ready = True
    issues = []

    # 1. Check database connectivity
    try:
        db.execute(text("SELECT 1;"))
        metrics_registry.database_connected.set(1.0)
    except Exception as e:
        is_ready = False
        issues.append(f"PostgreSQL unreachable: {e}")
        metrics_registry.database_connected.set(0.0)

    # 2. Check policy engine readiness
    if not default_policy_engine:
        is_ready = False
        issues.append("PolicyEngine is not initialized.")

    # 3. Check tool registry readiness
    if not default_tool_registry:
        is_ready = False
        issues.append("ToolRegistry is not initialized.")

    if not is_ready:
        logger.error(f"Readiness probe failed: {'; '.join(issues)}")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "not_ready",
                "service": settings.APP_NAME,
                "issues": issues,
                "timestamp": utc_now(),
            },
        )

    return {
        "status": "ready",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "timestamp": utc_now(),
    }


@router.get("/health/dependencies", summary="Detailed operational dependency status breakdown")
def dependency_health(db: Session = Depends(get_db)):
    """Provides granular status, latency, and capability breakdown of all sub-systems."""
    deps: Dict[str, Any] = {}

    # Database check with timing
    db_start = time.perf_counter()
    try:
        db.execute(text("SELECT 1;"))
        db_lat = round((time.perf_counter() - db_start) * 1000, 2)
        deps["postgresql"] = {
            "status": "healthy",
            "latency_ms": db_lat,
            "host": settings.POSTGRES_HOST,
            "port": settings.POSTGRES_PORT,
            "database": settings.POSTGRES_DB,
        }
    except Exception as e:
        deps["postgresql"] = {
            "status": "unhealthy",
            "error": str(e),
        }

    # Policy Engine check
    rule_count = len(default_policy_engine.policies) if default_policy_engine else 0
    deps["policy_engine"] = {
        "status": "healthy" if rule_count > 0 else "degraded",
        "active_rules_count": rule_count,
    }

    # Tool Registry check
    tool_count = len(default_tool_registry.list_tools()) if default_tool_registry else 0
    deps["tool_registry"] = {
        "status": "healthy" if tool_count > 0 else "degraded",
        "registered_tools_count": tool_count,
    }

    # Sandbox / Execution gateway
    deps["sandbox_execution"] = {
        "status": "healthy",
        "backend": "IN_PROCESS_GUARDED",
        "profiles": ["STRICT", "STANDARD", "RESEARCH", "DEVELOPER", "PRIVILEGED"],
    }

    # Backward compatibility aliases
    deps["database"] = deps["postgresql"]
    deps["rate_limiter"] = {
        "status": "healthy",
        "mode": "in_memory_single_instance",
        "limit_per_minute": settings.RATE_LIMIT_REQUESTS_PER_MINUTE,
        "burst": settings.RATE_LIMIT_BURST,
    }

    all_healthy = all(d.get("status") == "healthy" for d in deps.values())
    status_code = status.HTTP_200_OK if all_healthy else status.HTTP_503_SERVICE_UNAVAILABLE

    return JSONResponse(
        status_code=status_code,
        content={
            "status": "healthy" if all_healthy else "degraded",
            "environment": settings.ENVIRONMENT,
            "timestamp": utc_now(),
            "dependencies": deps,
        },
    )