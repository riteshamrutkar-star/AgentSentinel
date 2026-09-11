def test_api_policy_rules(client):
    res = client.get("/api/v1/policy/rules")
    assert res.status_code == 200
    rules = res.json()
    assert isinstance(rules, list)
    assert len(rules) > 0

def test_api_intercept_tool_call_allow(client):
    payload = {
        "session_id": "sess_api_1",
        "agent_id": "agent_api",
        "user_id": "user_api",
        "tool_name": "google_search",
        "arguments": {"query": "cybersecurity"},
        "role": "research_assistant",
        "action_type": "NETWORK",
    }
    res = client.post("/api/v1/intercept/tool-call", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["decision"] == "ALLOW"
    assert data["execution_allowed"] is True
    assert data["stored"] is True

def test_api_intercept_tool_call_block(client):
    payload = {
        "session_id": "sess_api_2",
        "agent_id": "agent_api",
        "user_id": "user_api",
        "tool_name": "read_system_file",
        "arguments": {"filepath": "/etc/shadow"},
        "role": "code_assistant",
        "action_type": "READ",
        "target_resource": "/etc/shadow",
    }
    res = client.post("/api/v1/intercept/tool-call", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["decision"] == "BLOCK"
    assert data["execution_allowed"] is False

def test_api_approval_lifecycle(client):
    # 1. Trigger an approval-required tool call
    payload = {
        "session_id": "sess_api_appr",
        "agent_id": "agent_api",
        "user_id": "user_api",
        "tool_name": "drop_database_table",
        "arguments": {"table_name": "test_table"},
        "role": "database_admin",
        "action_type": "DATABASE",
        "target_resource": "test_table",
    }
    int_res = client.post("/api/v1/intercept/tool-call", json=payload)
    assert int_res.status_code == 200
    event_id = int_res.json()["event_id"]

    # 2. Check approvals list
    appr_list_res = client.get("/api/v1/audit/approvals")
    assert appr_list_res.status_code == 200
    approvals = appr_list_res.json()
    assert any(a["event_id"] == event_id for a in approvals)

    # 3. Approve the action
    approve_payload = {"reviewer": "security_admin", "notes": "Approved for maintenance"}
    approve_res = client.post(f"/api/v1/audit/approvals/{event_id}/approve", json=approve_payload)
    assert approve_res.status_code == 200
    assert approve_res.json()["approval_status"] == "APPROVED"
    assert approve_res.json()["execution_allowed"] is True

def test_api_dashboard_endpoints(client):
    # Verify stats
    stats_res = client.get("/api/v1/dashboard/stats")
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert "total_events" in stats
    assert "allowed_count" in stats
    assert "blocked_count" in stats

    # Verify trend
    trend_res = client.get("/api/v1/dashboard/activity-trend")
    assert trend_res.status_code == 200
    assert isinstance(trend_res.json(), list)

    # Verify risk summary
    risk_res = client.get("/api/v1/dashboard/risk-summary")
    assert risk_res.status_code == 200
    risk = risk_res.json()
    assert "counts" in risk
    assert "percentages" in risk

    # Verify active sessions
    sess_res = client.get("/api/v1/dashboard/active-sessions")
    assert sess_res.status_code == 200
    assert isinstance(sess_res.json(), list)

def test_api_validation_error_handling(client):
    # Missing required session_id and tool_name
    invalid_payload = {"user_id": "test"}
    res = client.post("/api/v1/intercept/tool-call", json=invalid_payload)
    assert res.status_code == 422
    err = res.json()
    assert "detail" in err
