"""
Comprehensive Automated Unit & Integration Tests for Multi-Agent Security & Governance (Phase 0.4).
Covers Agent Identity, Capabilities, Trust Engine, Delegation, Privilege Escalation, Depth Limits,
Circular Chains, Tool Scoping, Message Interception, and REST APIs.
"""

from datetime import datetime, timedelta, timezone
import pytest

from app.multiagent.adapter import LangChainMultiAgentAdapter
from app.multiagent.config import multiagent_config
from app.multiagent.delegation import DelegationManager
from app.multiagent.escalation import PrivilegeEscalationDetector
from app.multiagent.interceptor import AgentMessageInterceptor
from app.multiagent.models import (
    AgentCapability,
    AgentIdentity,
    AgentMessage,
    AgentStatus,
    MessageType,
    TrustLevel,
    utc_now,
)
from app.multiagent.registry import AgentRegistry
from app.multiagent.trust import AgentTrustEngine


# --- 1. Agent Identity & Registry Tests ---

def test_agent_registration_and_lookup():
    registry = AgentRegistry()
    agent = AgentIdentity(
        agent_id="test_custom_analyst",
        name="Custom Analyst",
        role="research_assistant",
        agent_type="analyst",
        owner="sec_team",
        capabilities=[AgentCapability.SEARCH, AgentCapability.FILE_READ],
        trust_level=TrustLevel.TRUSTED,
        trust_score=0.85,
        status=AgentStatus.ACTIVE,
    )
    registry.register_agent(agent)

    retrieved = registry.get_agent("test_custom_analyst")
    assert retrieved is not None
    assert retrieved.agent_id == "test_custom_analyst"
    assert retrieved.role == "research_assistant"
    assert AgentCapability.SEARCH in retrieved.capabilities


def test_unknown_agent_validation_fails_closed():
    registry = AgentRegistry()
    is_valid, err = registry.validate_agent("unknown_shadow_agent")
    assert is_valid is False
    assert "not registered" in err.lower()


def test_revoked_agent_validation_fails_closed():
    registry = AgentRegistry()
    agent = AgentIdentity(
        agent_id="agent_to_revoke",
        name="Compromised Agent",
        capabilities=[AgentCapability.SEARCH],
        trust_level=TrustLevel.STANDARD,
        status=AgentStatus.ACTIVE,
    )
    registry.register_agent(agent)

    # Revoke
    success = registry.revoke_agent("agent_to_revoke")
    assert success is True

    # Validate fails closed
    is_valid, err = registry.validate_agent("agent_to_revoke")
    assert is_valid is False
    assert "revoked" in err.lower()


# --- 2. Trust Engine Tests ---

def test_trust_evaluation_baseline():
    registry = AgentRegistry()
    engine = AgentTrustEngine(registry=registry)

    # Test baseline evaluation for seeded trusted coordinator
    res = engine.evaluate_agent_trust("agent_research_coordinator")
    assert res.trust_level == TrustLevel.TRUSTED
    assert res.trust_score >= 0.75
    assert "agent_research_coordinator" in res.explanation


def test_trust_evaluation_fails_closed_on_unknown():
    registry = AgentRegistry()
    engine = AgentTrustEngine(registry=registry)

    res = engine.evaluate_agent_trust("nonexistent_agent_x")
    assert res.trust_level == TrustLevel.UNTRUSTED
    assert res.trust_score == 0.0


def test_trust_degradation_with_penalties():
    registry = AgentRegistry()
    engine = AgentTrustEngine(registry=registry)

    # Base trusted agent (0.85) receives escalation and depth penalties
    penalized = engine.evaluate_agent_trust(
        agent_id="agent_research_coordinator",
        context_penalties=["privilege_escalation", "depth_exceeded"],
    )
    assert penalized.trust_score < 0.85
    assert penalized.trust_level in (TrustLevel.STANDARD, TrustLevel.LIMITED)
    assert any("escalation" in f.lower() for f in penalized.factors)


# --- 3. Privilege Escalation & Delegation Guard Tests ---

def test_privilege_escalation_detection_subset_rule():
    detector = PrivilegeEscalationDetector()

    # Delegator has only SEARCH, FILE_READ, DELEGATION
    delegator = AgentIdentity(
        agent_id="delegator_1",
        name="Delegator 1",
        capabilities=[AgentCapability.SEARCH, AgentCapability.FILE_READ, AgentCapability.DELEGATION],
    )

    # Requesting DATABASE_WRITE exceeds authorized capabilities
    is_esc, msg, unauthorized = detector.check_capability_escalation(
        delegator=delegator,
        requested_capabilities=[AgentCapability.SEARCH, AgentCapability.DATABASE_WRITE],
    )
    assert is_esc is True
    assert AgentCapability.DATABASE_WRITE in unauthorized
    assert "Privilege escalation detected" in msg


def test_delegation_prohibited_without_delegation_capability():
    detector = PrivilegeEscalationDetector()

    # Worker has SEARCH and FILE_READ but NOT DELEGATION
    worker = AgentIdentity(
        agent_id="worker_leaf",
        name="Leaf Worker",
        capabilities=[AgentCapability.SEARCH, AgentCapability.FILE_READ],
    )

    is_esc, msg, unauthorized = detector.check_capability_escalation(
        delegator=worker,
        requested_capabilities=[AgentCapability.SEARCH],
    )
    assert is_esc is True
    assert "lacks explicit DELEGATION capability" in msg


def test_delegation_depth_limit_enforcement():
    detector = PrivilegeEscalationDetector()

    # Depths 1, 2, 3 permitted
    assert detector.check_delegation_depth(1)[0] is False
    assert detector.check_delegation_depth(2)[0] is False
    assert detector.check_delegation_depth(3)[0] is False

    # Depth 4 exceeds maximum
    depth_exceeded, msg = detector.check_delegation_depth(4)
    assert depth_exceeded is True
    assert "exceeded configured maximum" in msg


def test_circular_delegation_detection():
    detector = PrivilegeEscalationDetector()

    provenance = ["agent_alpha", "agent_beta", "agent_gamma"]

    # Target is new -> allowed
    is_circ, _ = detector.check_circular_delegation("agent_delta", provenance)
    assert is_circ is False

    # Target is agent_alpha -> circular loop!
    is_circ, msg = detector.check_circular_delegation("agent_alpha", provenance)
    assert is_circ is True
    assert "Circular delegation chain detected" in msg


# --- 4. Delegation Manager & Scope Validation Tests ---

def test_delegation_lifecycle():
    manager = DelegationManager()

    # Issue
    delegation = manager.issue_delegation(
        source_agent_id="agent_alpha",
        target_agent_id="agent_beta",
        session_id="sess_del_1",
        delegated_capabilities=[AgentCapability.SEARCH],
        resource_scope="*",
    )
    assert delegation.delegation_id.startswith("del_")
    assert delegation.status == "ACTIVE"

    # Validate tool within scope
    is_auth, _, _ = manager.validate_delegated_tool_call(
        delegation_id=delegation.delegation_id,
        executing_agent_id="agent_beta",
        tool_name="google_search",
    )
    assert is_auth is True

    # Validate tool outside scope (requires FILE_WRITE)
    is_auth, reason, _ = manager.validate_delegated_tool_call(
        delegation_id=delegation.delegation_id,
        executing_agent_id="agent_beta",
        tool_name="write_workspace_file",
    )
    assert is_auth is False
    assert "capability scope exceeded" in reason

    # Impersonation test: wrong executing agent
    is_auth, reason, _ = manager.validate_delegated_tool_call(
        delegation_id=delegation.delegation_id,
        executing_agent_id="imposter_agent",
        tool_name="google_search",
    )
    assert is_auth is False
    assert "impersonation" in reason.lower()

    # Revoke
    revoked = manager.revoke_delegation(delegation.delegation_id)
    assert revoked is True

    # Validation after revoke fails
    is_auth, reason, _ = manager.validate_delegated_tool_call(
        delegation_id=delegation.delegation_id,
        executing_agent_id="agent_beta",
        tool_name="google_search",
    )
    assert is_auth is False
    assert "no longer active" in reason


def test_delegation_expired_token_fails_closed():
    manager = DelegationManager()
    expired_time = datetime.now(timezone.utc) - timedelta(minutes=5)

    delegation = manager.issue_delegation(
        source_agent_id="agent_alpha",
        target_agent_id="agent_beta",
        session_id="sess_del_exp",
        delegated_capabilities=[AgentCapability.SEARCH],
        expires_at=expired_time,
    )

    is_auth, reason, _ = manager.validate_delegated_tool_call(
        delegation_id=delegation.delegation_id,
        executing_agent_id="agent_beta",
        tool_name="google_search",
    )
    assert is_auth is False
    assert "expired" in reason.lower()


# --- 5. Message Interceptor Tests ---

def test_message_interceptor_valid_flow():
    interceptor = AgentMessageInterceptor()

    msg = AgentMessage(
        message_id="msg_valid_1",
        sender_agent_id="agent_research_coordinator",
        recipient_agent_id="agent_research_worker",
        session_id="sess_msg_1",
        requested_action="Search cybersecurity frameworks",
        requested_capabilities=[AgentCapability.SEARCH],
    )

    decision = interceptor.intercept_message(msg)
    assert decision.decision == "ALLOW"
    assert decision.execution_allowed is True
    assert decision.delegation_id is not None
    assert decision.escalation_detected is False


def test_message_interceptor_blocks_privilege_escalation():
    interceptor = AgentMessageInterceptor()

    # Coordinator does NOT possess DATABASE_WRITE
    msg = AgentMessage(
        message_id="msg_esc_1",
        sender_agent_id="agent_research_coordinator",
        recipient_agent_id="agent_research_worker",
        session_id="sess_msg_2",
        requested_action="Drop user audit tables",
        requested_capabilities=[AgentCapability.DATABASE_WRITE],
    )

    decision = interceptor.intercept_message(msg)
    assert decision.decision == "BLOCK"
    assert decision.execution_allowed is False
    assert decision.escalation_detected is True
    assert "PRIVILEGE_ESCALATION_BLOCKED" in decision.reason


def test_message_interceptor_blocks_circular_chain():
    interceptor = AgentMessageInterceptor()

    msg = AgentMessage(
        message_id="msg_circ_1",
        sender_agent_id="agent_research_worker",
        recipient_agent_id="agent_research_coordinator",
        session_id="sess_msg_3",
        requested_action="Delegate back to coordinator",
        requested_capabilities=[AgentCapability.SEARCH],
        provenance=["agent_research_coordinator", "agent_research_worker"],
    )

    decision = interceptor.intercept_message(msg)
    assert decision.decision == "BLOCK"
    assert decision.escalation_detected is True
    assert "CIRCULAR_DELEGATION_PROHIBITED" in decision.reason


def test_message_interceptor_blocks_untrusted_sender():
    interceptor = AgentMessageInterceptor()

    msg = AgentMessage(
        message_id="msg_untrusted_1",
        sender_agent_id="agent_untrusted_bot",
        recipient_agent_id="agent_research_worker",
        session_id="sess_msg_4",
        requested_action="Attempt unauthorized delegation",
        requested_capabilities=[AgentCapability.SEARCH],
    )

    decision = interceptor.intercept_message(msg)
    assert decision.decision == "BLOCK"
    assert decision.execution_allowed is False


# --- 6. Framework Adapter & End-to-End Delegated Execution Tests ---

def test_langchain_adapter_flow(db_session):
    adapter = LangChainMultiAgentAdapter()

    # 1. Coordinator delegates SEARCH to worker
    decision = adapter.delegate_action(
        sender_agent_id="agent_research_coordinator",
        recipient_agent_id="agent_research_worker",
        session_id="sess_adapter_test",
        action_name="Search for AI agent security standards",
        capabilities=[AgentCapability.SEARCH],
        db=db_session,
    )
    assert decision.decision == "ALLOW"
    assert decision.delegation_id is not None

    # 2. Worker executes tool under granted delegation token
    tool_result = adapter.execute_delegated_tool(
        delegation_id=decision.delegation_id,
        executing_agent_id="agent_research_worker",
        tool_name="google_search",
        tool_input={"query": "AI agent runtime security"},
        session_id="sess_adapter_test",
        db=db_session,
    )
    assert tool_result["status"] == "SUCCESS"
    assert tool_result["verdict"] == "ALLOW"
    assert "Search Results" in tool_result["output"]

    # 3. Worker attempts unauthorized tool outside delegated scope
    unauth_result = adapter.execute_delegated_tool(
        delegation_id=decision.delegation_id,
        executing_agent_id="agent_research_worker",
        tool_name="write_workspace_file",
        tool_input={"filepath": "hack.txt", "content": "exfiltration"},
        session_id="sess_adapter_test",
        db=db_session,
    )
    assert unauth_result["status"] == "BLOCKED"
    assert unauth_result["verdict"] == "BLOCK"


# --- 7. Multi-Agent REST API Tests ---

def test_api_list_and_register_agents(client):
    # List agents
    res = client.get("/api/v1/agents")
    assert res.status_code == 200
    agents = res.json()
    assert len(agents) >= 5

    # Register new agent
    payload = {
        "agent_id": "api_test_reviewer",
        "name": "API Test Reviewer",
        "role": "code_assistant",
        "capabilities": ["FILE_READ", "FILE_WRITE"],
        "trust_level": "STANDARD",
    }
    create_res = client.post("/api/v1/agents", json=payload)
    assert create_res.status_code == 201
    data = create_res.json()
    assert data["agent_id"] == "api_test_reviewer"

    # Get agent details
    get_res = client.get("/api/v1/agents/api_test_reviewer")
    assert get_res.status_code == 200
    assert get_res.json()["name"] == "API Test Reviewer"


def test_api_evaluate_trust(client):
    res = client.get("/api/v1/agents/agent_research_coordinator/trust")
    assert res.status_code == 200
    data = res.json()
    assert data["trust_level"] == "TRUSTED"
    assert 0.0 <= data["trust_score"] <= 1.0


def test_api_delegation_request_and_revoke(client):
    # Request delegation
    payload = {
        "source_agent_id": "agent_research_coordinator",
        "target_agent_id": "agent_research_worker",
        "session_id": "sess_api_del",
        "action_name": "API Delegation",
        "capabilities": ["SEARCH"],
    }
    del_res = client.post("/api/v1/delegation/request", json=payload)
    assert del_res.status_code == 200
    del_data = del_res.json()
    assert del_data["decision"] == "ALLOW"
    del_id = del_data["delegation_id"]

    # Get delegation
    get_del = client.get(f"/api/v1/delegation/{del_id}")
    assert get_del.status_code == 200
    assert get_del.json()["status"] == "ACTIVE"

    # Revoke delegation
    rev_res = client.post(f"/api/v1/delegation/{del_id}/revoke")
    assert rev_res.status_code == 200
    assert rev_res.json()["status"] == "REVOKED"
