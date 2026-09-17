"""
AgentSentinel Phase 0.8: Prometheus Metrics Scrape Endpoint.
Exposes standard text/plain metrics conforming to Prometheus exposition format 0.0.4.
"""

from fastapi import APIRouter
from fastapi.responses import Response

from app.observability.metrics import metrics_registry

router = APIRouter(tags=["Observability & Metrics"])


@router.get(
    "/metrics",
    summary="Scrape Prometheus-compatible operational and security metrics",
    response_class=Response,
)
def get_metrics():
    """
    Returns application metrics in Prometheus text exposition format.
    Suitable for automated scraping by Prometheus, VictoriaMetrics, or Datadog agent.
    """
    content = metrics_registry.export_text()
    return Response(
        content=content,
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )