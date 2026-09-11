"""
Unit tests for Risk Intelligence REST API endpoints (/api/v1/risk/*).
"""

import pytest


def test_get_session_risk_not_found(client):
    res = client.get("/api/v1/risk/session/nonexistent_session_123")
    assert res.status_code == 404
    assert "No security events found" in res.json()["detail"]


def test_get_session_risk_breakdown(client):
    # Seed an event via intercept
    payload = {
        "session_id": "sess_risk_api_test",
        "agent_id": "agent_risk_test",
        "user_id": "user_risk_test",
        "tool_name": "web_search",
        "arguments": {"query": "threat intelligence"},
        "role": "research_assistant",
        "action_type": "NETWORK",
    }
    int_res = client.post("/api/v1/intercept/tool-call", json=payload)
    assert int_res.status_code == 200

    # Query session risk breakdown
    res = client.get("/api/v1/risk/session/sess_risk_api_test")
    assert res.status_code == 200
    data = res.json()
    assert "overall_score" in data
    assert "severity" in data
    assert "primary_detector" in data
    assert "detector_contributions" in data
    assert "detector_results" in data
    assert "top_risk_factors" in data
    assert "evidence" in data
    assert isinstance(data["overall_score"], float)
    assert 0.0 <= data["overall_score"] <= 1.0


def test_post_risk_analyze_benign(client):
    payload = {
        "session_id": "sess_analyze_benign",
        "tool_name": "calculator",
        "arguments": {"expression": "2+2"},
        "role": "research_assistant",
        "action_type": "READ",
        "target_resource": "math_engine"
    }
    res = client.post("/api/v1/risk/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert 0.0 <= data["overall_score"] <= 1.0
    assert data["severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert "StatisticalBaselineDetector" in data["detector_results"]


def test_post_risk_analyze_high_risk(client):
    payload = {
        "session_id": "sess_analyze_suspicious",
        "tool_name": "drop_database_table",
        "arguments": {"table": "users"},
        "role": "readonly_viewer",
        "action_type": "DATABASE",
        "target_resource": "users"
    }
    res = client.post("/api/v1/risk/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["overall_score"] > 0.30
    assert len(data["top_risk_factors"]) > 0
