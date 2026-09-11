def test_root_endpoint(client):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "Welcome to AgentSentinel" in data["message"]
    assert data["docs"] == "/docs"
    assert data["health"] == "/health"

def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "AgentSentinel"
    assert "version" in data

def test_intercept_health_endpoint(client):
    response = client.get("/api/v1/intercept/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["active_rules_count"] > 0
