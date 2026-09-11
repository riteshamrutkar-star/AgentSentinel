"""
AgentSentinel Phase 0.5: Secure Execution Gateway.
The mandatory, authoritative execution boundary mediating all tool invocations.
Enforces capability containment, approval binding, sandbox profile jailing,
filesystem/network/process guards, timeout enforcement, secret redaction, and durable audit.
"""

import time
import uuid
from typing import Any, Callable, Dict, Optional, Tuple
from sqlalchemy.orm import Session

from app.core.logger import logger
from app.db.models import ApprovalModel, EventModel
from app.execution.config import execution_config
from app.execution.filesystem import default_filesystem_sandbox
from app.execution.models import (
    ExecutionBackend,
    ExecutionContext,
    ExecutionOutput,
    ExecutionState,
    SandboxProfile,
    ToolCategory,
    ToolDefinition,
    utc_now,
)
from app.execution.network import default_network_guard
from app.execution.process import default_process_guard
from app.execution.registry import default_tool_registry
from app.execution.sandbox import default_docker_runner, default_inprocess_runner
from app.execution.secrets import default_secret_protector
from app.execution.state import ExecutionStateMachine
from app.multiagent.delegation import default_delegation_manager
from app.multiagent.models import AgentCapability, AgentStatus
from app.multiagent.registry import default_agent_registry


class SecureExecutionGateway:
    """
    Mandatory execution gateway between policy/anomaly authorization and physical execution.
    Fails closed on any constraint violation or unexpected exception.
    """

    def __init__(self):
        self.tool_registry = default_tool_registry
        self.filesystem_sandbox = default_filesystem_sandbox
        self.network_guard = default_network_guard
        self.process_guard = default_process_guard
        self.secret_protector = default_secret_protector
        self.inprocess_runner = default_inprocess_runner
        self.docker_runner = default_docker_runner

    def execute(
        self,
        context: ExecutionContext,
        handler: Optional[Callable[..., Any]] = None,
        db: Optional[Session] = None,
    ) -> ExecutionOutput:
        """
        Main entry point for executing an approved tool call.
        Enforces 14 distinct security checks before dispatching execution.
        """
        start_time = time.perf_counter()
        execution_id = context.execution_id or f"exec_{uuid.uuid4().hex[:10]}"
        state = ExecutionState.REQUESTED

        try:
            # -------------------------------------------------------------
            # CHECK 1: Resolve Tool in Authoritative ToolRegistry
            # -------------------------------------------------------------
            tool_def = self.tool_registry.get_tool(context.tool_name or context.tool_id)
            if not tool_def:
                return self._create_blocked_output(
                    execution_id=execution_id,
                    reason=f"UNREGISTERED_TOOL_BLOCKED: Tool '{context.tool_name}' is not registered in ToolRegistry.",
                    start_time=start_time,
                    db=db,
                    context=context,
                )

            if not tool_def.enabled:
                return self._create_blocked_output(
                    execution_id=execution_id,
                    reason=f"TOOL_DISABLED_BLOCKED: Tool '{tool_def.name}' is currently disabled by security policy.",
                    start_time=start_time,
                    db=db,
                    context=context,
                )

            state = ExecutionStateMachine.transition(state, ExecutionState.VALIDATED)

            # -------------------------------------------------------------
            # CHECK 2: Validate Agent Identity & Status
            # -------------------------------------------------------------
            agent = default_agent_registry.get_agent(context.agent_id, db=db)
            if not agent:
                return self._create_blocked_output(
                    execution_id=execution_id,
                    reason=f"UNKNOWN_AGENT_BLOCKED: Executing agent '{context.agent_id}' is not registered in AgentRegistry.",
                    start_time=start_time,
                    db=db,
                    context=context,
                )

            if agent.status == AgentStatus.REVOKED:
                return self._create_blocked_output(
                    execution_id=execution_id,
                    reason=f"REVOKED_AGENT_BLOCKED: Agent '{context.agent_id}' has been REVOKED and is prohibited from execution.",
                    start_time=start_time,
                    db=db,
                    context=context,
                )

            # -------------------------------------------------------------
            # CHECK 3: Capability Containment (Agent Caps >= Tool Required)
            # -------------------------------------------------------------
            agent_caps = set(agent.capabilities)
            if tool_def.required_capability not in agent_caps:
                return self._create_blocked_output(
                    execution_id=execution_id,
                    reason=(
                        f"CAPABILITY_MISMATCH_BLOCKED: Agent '{context.agent_id}' lacks required capability "
                        f"'{tool_def.required_capability.value}' for tool '{tool_def.name}'."
                    ),
                    start_time=start_time,
                    db=db,
                    context=context,
                )

            # -------------------------------------------------------------
            # CHECK 4: Delegation Token Validation & Scope Containment
            # -------------------------------------------------------------
            if context.delegation_id:
                del_ctx = default_delegation_manager.get_delegation(context.delegation_id, db=db)
                if not del_ctx:
                    return self._create_blocked_output(
                        execution_id=execution_id,
                        reason=f"INVALID_DELEGATION_TOKEN: Delegation token '{context.delegation_id}' not found.",
                        start_time=start_time,
                        db=db,
                        context=context,
                    )

                if del_ctx.status != "ACTIVE":
                    return self._create_blocked_output(
                        execution_id=execution_id,
                        reason=f"REVOKED_DELEGATION_TOKEN: Delegation token '{context.delegation_id}' is inactive or revoked (status='{del_ctx.status}').",
                        start_time=start_time,
                        db=db,
                        context=context,
                    )

                if del_ctx.expires_at and del_ctx.expires_at < utc_now():
                    return self._create_blocked_output(
                        execution_id=execution_id,
                        reason=f"EXPIRED_DELEGATION_TOKEN: Delegation token '{context.delegation_id}' has expired.",
                        start_time=start_time,
                        db=db,
                        context=context,
                    )

                # Token must be bound strictly to the executing agent
                if del_ctx.target_agent_id != context.agent_id:
                    return self._create_blocked_output(
                        execution_id=execution_id,
                        reason=(
                            f"TOKEN_HIJACKING_BLOCKED: Delegation token '{context.delegation_id}' is bound to "
                            f"agent '{del_ctx.target_agent_id}', but presented by '{context.agent_id}'."
                        ),
                        start_time=start_time,
                        db=db,
                        context=context,
                    )

                # Delegated capabilities must contain tool required capability
                del_caps = set(del_ctx.delegated_capabilities)
                if tool_def.required_capability not in del_caps:
                    return self._create_blocked_output(
                        execution_id=execution_id,
                        reason=(
                            f"DELEGATION_SCOPE_OVERREACH_BLOCKED: Delegation token does not grant required "
                            f"capability '{tool_def.required_capability.value}'."
                        ),
                        start_time=start_time,
                        db=db,
                        context=context,
                    )

            # -------------------------------------------------------------
            # CHECK 5: Policy Decision Enforcement
            # -------------------------------------------------------------
            if context.policy_decision == "BLOCK" or context.policy_decision == "DENY":
                return self._create_blocked_output(
                    execution_id=execution_id,
                    reason=f"POLICY_DECISION_BLOCKED: Action was blocked by static security policy.",
                    start_time=start_time,
                    db=db,
                    context=context,
                )

            # -------------------------------------------------------------
            # CHECK 6: Approval Scope & Binding
            # -------------------------------------------------------------
            needs_approval = tool_def.approval_required or context.policy_decision == "REQUIRE_APPROVAL"
            if needs_approval:
                if not context.approval_id and not context.approval_event_id:
                    state = ExecutionStateMachine.transition(state, ExecutionState.PENDING_APPROVAL)
                    return self._create_output(
                        execution_id=execution_id,
                        status=ExecutionState.PENDING_APPROVAL,
                        output=f"APPROVAL_REQUIRED: Action '{tool_def.name}' requires explicit administrator sign-off.",
                        elapsed_ms=round((time.perf_counter() - start_time) * 1000, 2),
                        context=context,
                    )

                # Validate approval record in database
                if db:
                    target_event_id = context.approval_event_id or context.approval_id
                    approval_rec = db.query(ApprovalModel).filter(ApprovalModel.event_id == target_event_id).first()
                    if not approval_rec:
                        return self._create_blocked_output(
                            execution_id=execution_id,
                            reason=f"APPROVAL_NOT_FOUND: No approved record exists for ID '{target_event_id}'.",
                            start_time=start_time,
                            db=db,
                            context=context,
                        )

                    if approval_rec.status != "APPROVED":
                        return self._create_blocked_output(
                            execution_id=execution_id,
                            reason=f"APPROVAL_NOT_GRANTED: Approval record '{target_event_id}' has status '{approval_rec.status}'.",
                            start_time=start_time,
                            db=db,
                            context=context,
                        )

                    # Bind approval to the exact agent and tool via associated EventModel
                    evt = approval_rec.event or db.query(EventModel).filter(EventModel.event_id == approval_rec.event_id).first()
                    expected_agent = evt.agent_id if evt else getattr(approval_rec, "agent_id", context.agent_id)
                    expected_tool = evt.tool_name if evt else getattr(approval_rec, "tool_name", tool_def.name)
                    expected_resource = evt.target_resource if evt else getattr(approval_rec, "target_resource", "")

                    if expected_agent != context.agent_id or expected_tool != tool_def.name:
                        return self._create_blocked_output(
                            execution_id=execution_id,
                            reason=(
                                f"APPROVAL_BINDING_MISMATCH: Approval '{target_event_id}' was issued for "
                                f"Agent='{expected_agent}', Tool='{expected_tool}', but presented for "
                                f"Agent='{context.agent_id}', Tool='{tool_def.name}'."
                            ),
                            start_time=start_time,
                            db=db,
                            context=context,
                        )

                    # Bind approval to resource scope if specified
                    if expected_resource and context.resource_scope:
                        if expected_resource != context.resource_scope:
                            return self._create_blocked_output(
                                execution_id=execution_id,
                                reason=(
                                    f"APPROVAL_RESOURCE_MISMATCH: Approval authorized resource "
                                    f"'{expected_resource}', but attempted '{context.resource_scope}'."
                                ),
                                start_time=start_time,
                                db=db,
                                context=context,
                            )

                state = ExecutionStateMachine.transition(state, ExecutionState.APPROVED)

            # -------------------------------------------------------------
            # CHECK 7: Resolve & Validate Sandbox Profile
            # -------------------------------------------------------------
            profile_name = tool_def.sandbox_profile_name or "STANDARD"
            standard_profiles = execution_config.get_standard_profiles()
            if context.sandbox_profile and context.sandbox_profile.name in standard_profiles and context.sandbox_profile.name != "STANDARD":
                sandbox_profile = standard_profiles[context.sandbox_profile.name]
            else:
                sandbox_profile = standard_profiles.get(profile_name, standard_profiles["STANDARD"])
            context.sandbox_profile = sandbox_profile

            # -------------------------------------------------------------
            # CHECK 8: Filesystem Boundary Pre-Checks
            # -------------------------------------------------------------
            args = dict(context.arguments or {})
            filepath_arg = args.get("filepath") or args.get("path") or (context.resource_scope if tool_def.filesystem_required else None)

            if filepath_arg and isinstance(filepath_arg, str):
                if tool_def.category == ToolCategory.FILESYSTEM and "write" in tool_def.name.lower():
                    # Write validation
                    ok, fs_err, canon_path = self.filesystem_sandbox.validate_write_path(
                        raw_path=filepath_arg,
                        allowed_roots=sandbox_profile.writable_paths,
                    )
                    if not ok:
                        return self._create_blocked_output(
                            execution_id=execution_id,
                            reason=f"FILESYSTEM_GUARD_BLOCKED: {fs_err}",
                            start_time=start_time,
                            db=db,
                            context=context,
                        )
                else:
                    # Read validation
                    allow_sys = (tool_def.category == ToolCategory.CREDENTIAL)
                    ok, fs_err, canon_path = self.filesystem_sandbox.validate_read_path(
                        raw_path=filepath_arg,
                        allowed_roots=sandbox_profile.readable_paths,
                        allow_system=allow_sys,
                    )
                    if not ok:
                        return self._create_blocked_output(
                            execution_id=execution_id,
                            reason=f"FILESYSTEM_GUARD_BLOCKED: {fs_err}",
                            start_time=start_time,
                            db=db,
                            context=context,
                        )

            # -------------------------------------------------------------
            # CHECK 9: Network Egress Pre-Checks
            # -------------------------------------------------------------
            if tool_def.network_required or tool_def.category == ToolCategory.NETWORK:
                dest = args.get("url") or args.get("host") or args.get("endpoint") or args.get("domain") or args.get("destination")
                if not dest and context.resource_scope and ("http" in str(context.resource_scope) or "." in str(context.resource_scope)):
                    dest = str(context.resource_scope)
                if not dest:
                    dest = tool_def.metadata.get("default_host", "google.com")

                dest_str = str(dest)
                if dest_str:
                    net_ok, net_err = self.network_guard.validate_egress(
                        target_destination=dest_str,
                        network_allowed=sandbox_profile.network_allowed,
                        custom_allowlist=sandbox_profile.allowed_domains,
                    )
                    if not net_ok:
                        return self._create_blocked_output(
                            execution_id=execution_id,
                            reason=f"NETWORK_GUARD_BLOCKED: {net_err}",
                            start_time=start_time,
                            db=db,
                            context=context,
                        )

            # -------------------------------------------------------------
            # CHECK 10: Process Execution Pre-Checks
            # -------------------------------------------------------------
            if tool_def.process_execution_required or tool_def.category == ToolCategory.PROCESS:
                cmd = args.get("command") or args.get("cmd") or args.get("executable")
                if cmd:
                    proc_ok, proc_err, safe_args = self.process_guard.validate_command(
                        command=cmd,
                        working_dir=args.get("working_dir"),
                        process_allowed=sandbox_profile.process_execution_allowed,
                    )
                    if not proc_ok:
                        return self._create_blocked_output(
                            execution_id=execution_id,
                            reason=f"PROCESS_GUARD_BLOCKED: {proc_err}",
                            start_time=start_time,
                            db=db,
                            context=context,
                        )

            # -------------------------------------------------------------
            # CHECK 11: Sandbox Selection & Dispatch
            # -------------------------------------------------------------
            target_func = handler or tool_def.handler
            if not target_func:
                return self._create_blocked_output(
                    execution_id=execution_id,
                    reason=f"NO_EXECUTION_HANDLER: No callable handler bound for tool '{tool_def.name}'.",
                    start_time=start_time,
                    db=db,
                    context=context,
                )

            # Check if Container Sandbox Required
            if tool_def.sandbox_required:
                if not self.docker_runner.is_available():
                    # Fail closed if required sandbox is not available
                    return self._create_blocked_output(
                        execution_id=execution_id,
                        reason="SANDBOX_UNAVAILABLE: Tool requires Docker container sandbox, but Docker daemon is not active or accessible.",
                        start_time=start_time,
                        db=db,
                        context=context,
                    )
                runner = self.docker_runner
            else:
                runner = self.inprocess_runner

            state = ExecutionStateMachine.transition(state, ExecutionState.RUNNING)

            # -------------------------------------------------------------
            # STEP 12: Dispatch Execution with Timeout Bounding
            # -------------------------------------------------------------
            try:
                exit_code, raw_output, run_ms, backend = runner.run(
                    context=context,
                    tool_def=tool_def,
                    func=target_func,
                    arguments=args,
                )
            except TimeoutError as te:
                state = ExecutionStateMachine.transition(state, ExecutionState.TIMEOUT)
                return self._create_output(
                    execution_id=execution_id,
                    status=ExecutionState.TIMEOUT,
                    output=f"EXECUTION_TIMEOUT: {str(te)}",
                    elapsed_ms=round((time.perf_counter() - start_time) * 1000, 2),
                    error_message=str(te),
                    context=context,
                )
            except Exception as exc:
                state = ExecutionStateMachine.transition(state, ExecutionState.FAILED)
                return self._create_output(
                    execution_id=execution_id,
                    status=ExecutionState.FAILED,
                    output=f"EXECUTION_FAILED: {str(exc)}",
                    elapsed_ms=round((time.perf_counter() - start_time) * 1000, 2),
                    error_message=str(exc),
                    context=context,
                )

            # -------------------------------------------------------------
            # CHECK 13: Output Security & Secret Redaction
            # -------------------------------------------------------------
            # Check for critical exfiltration secrets that must be blocked
            if self.secret_protector.should_block_on_secret(raw_output):
                state = ExecutionStateMachine.transition(state, ExecutionState.BLOCKED)
                return self._create_blocked_output(
                    execution_id=execution_id,
                    reason="OUTPUT_SECURITY_BLOCKED: Tool output contains high-risk credential or private key exfiltration pattern.",
                    start_time=start_time,
                    db=db,
                    context=context,
                )

            # Sanitize / redact any other secrets
            redaction_res = self.secret_protector.redact_secrets(raw_output)
            sanitized = redaction_res.sanitized_text

            # Enforce output byte limit
            if len(sanitized.encode("utf-8")) > execution_config.MAX_OUTPUT_BYTES:
                sanitized = sanitized[:execution_config.MAX_OUTPUT_BYTES] + "\n[OUTPUT_TRUNCATED: Exceeded max byte size]"

            state = ExecutionStateMachine.transition(state, ExecutionState.COMPLETED)
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

            output = ExecutionOutput(
                execution_id=execution_id,
                status=ExecutionState.COMPLETED,
                raw_output=raw_output,
                sanitized_output=sanitized,
                exit_code=exit_code,
                execution_time_ms=elapsed_ms,
                execution_backend=backend,
                redacted=redaction_res.redacted,
                detected_secrets=redaction_res.detected_secrets,
                metadata={
                    "agent_id": context.agent_id,
                    "tool_id": tool_def.tool_id,
                    "sandbox_profile": sandbox_profile.name,
                    "execution_mode": backend.value,
                },
            )

            # -------------------------------------------------------------
            # STEP 14: Audit Execution Record in PostgreSQL
            # -------------------------------------------------------------
            self._record_execution_audit(output, context, db)
            return output

        except Exception as unhandled:
            # Universal Fail-Closed Guarantee
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.critical(f"SecureExecutionGateway unexpected exception: {unhandled}", exc_info=True)
            return self._create_blocked_output(
                execution_id=execution_id,
                reason=f"GATEWAY_FAIL_CLOSED: Unexpected execution control exception: {str(unhandled)}",
                start_time=start_time,
                db=db,
                context=context,
            )

    def _create_blocked_output(
        self,
        execution_id: str,
        reason: str,
        start_time: float,
        db: Optional[Session] = None,
        context: Optional[ExecutionContext] = None,
    ) -> ExecutionOutput:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        out = ExecutionOutput(
            execution_id=execution_id,
            status=ExecutionState.BLOCKED,
            sanitized_output=f"SECURITY_GATEWAY_BLOCKED: {reason}",
            exit_code=1,
            execution_time_ms=elapsed_ms,
            execution_backend=ExecutionBackend.IN_PROCESS_GUARDED,
            redacted=False,
            detected_secrets=[],
            error_message=reason,
            metadata={"decision": "BLOCK", "reason": reason},
        )
        if context and db:
            self._record_execution_audit(out, context, db)
        return out

    def _create_output(
        self,
        execution_id: str,
        status: ExecutionState,
        output: str,
        elapsed_ms: float,
        error_message: Optional[str] = None,
        context: Optional[ExecutionContext] = None,
    ) -> ExecutionOutput:
        return ExecutionOutput(
            execution_id=execution_id,
            status=status,
            sanitized_output=output,
            exit_code=0 if status == ExecutionState.COMPLETED else 1,
            execution_time_ms=elapsed_ms,
            execution_backend=ExecutionBackend.IN_PROCESS_GUARDED,
            redacted=False,
            detected_secrets=[],
            error_message=error_message,
            metadata={"status": status.value},
        )

    def _record_execution_audit(
        self,
        output: ExecutionOutput,
        context: ExecutionContext,
        db: Optional[Session],
    ):
        """Persists durable execution record in PostgreSQL if db session provided."""
        if not db:
            return
        try:
            # We will use ExecutionModel once defined in db.models
            from app.db.models import ExecutionModel
            rec = ExecutionModel(
                execution_id=output.execution_id,
                session_id=context.session_id,
                agent_id=context.agent_id,
                tool_name=context.tool_name or context.tool_id,
                status=output.status.value,
                execution_backend=output.execution_backend.value,
                sandbox_profile=context.sandbox_profile.name if context.sandbox_profile else "STANDARD",
                execution_time_ms=output.execution_time_ms,
                exit_code=output.exit_code,
                redacted=output.redacted,
                detected_secrets_json=output.detected_secrets,
                error_message=output.error_message,
                sanitized_output_preview=output.sanitized_output[:500] if output.sanitized_output else "",
            )
            db.add(rec)
            db.commit()
        except Exception as e:
            try:
                db.rollback()
            except Exception:
                pass
            logger.warning(f"Could not persist ExecutionModel record: {e}")


default_execution_gateway = SecureExecutionGateway()
