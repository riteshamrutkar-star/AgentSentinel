from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_distributed_status_endpoint():
    response = client.get("/api/v1/distributed/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "operational"
    assert data["cluster"]["mode"] == "ACTIVE_ACTIVE_REPLICAS"
    assert len(data["cluster"]["replicas"]) == 2
    assert data["spof_disclosure"]["single_redis_coordinator"] is True
    assert data["spof_disclosure"]["single_postgres_primary"] is True
    assert data["spof_disclosure"]["is_ha_cluster"] is False
    assert len(data["ecosystem_adapters"]) == 5
    assert len(data["siem_connectors"]) == 3
    assert "default" in data["namespaces"]


def test_distributed_webhooks_endpoint():
    response = client.get("/api/v1/distributed/webhooks")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1


def test_distributed_webhooks_test_delivery():
    response = client.post(
        "/api/v1/distributed/webhooks/test",
        json={
            "destination": "https://sec-lake.internal/webhooks",
            "namespace": "production",
            "event_type": "tool_intercept.blocked",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "DELIVERED"
    assert data["destination"] == "https://sec-lake.internal/webhooks"
    assert data["signature_header"].startswith("sha256=")
    assert "timestamp_header" in data


def test_distributed_metrics_endpoint():
    response = client.get("/api/v1/distributed/metrics")
    assert response.status_code == 200
    data = response.json()
    assert data["phase"] in ("v0.9", "v0.9.0")
    assert "interceptor_throughput" in data or "concurrent_throughput" in data
    assert data["distributed_locking"]["mutual_exclusion_violations"] == 0
    assert data["idempotency_deduplication"]["duplicate_execution_rate_pct"] == 0.0
