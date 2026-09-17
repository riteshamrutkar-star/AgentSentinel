import time
import uuid
from typing import Optional
from sqlalchemy.orm import Session

from app.anomaly.detector import default_anomaly_detector
from app.audit.service import record_audit_entry
from app.core.logger import logger
from app.events.factory import apply_decision, enrich_event_security
from app.events.schema import PolicyResult, SensitivityLevel
from app.interceptor.normalizer import normalize_tool_call_request
from app.interceptor.schema import InterceptorResponse, ToolCallRequest
from app.multiagent.delegation import default_delegation_manager
from app.multiagent.registry import default_agent_registry
from app.policy.engine import default_policy_engine

def intercept_tool_call(request: ToolCallRequest, db: Session) -> InterceptorResponse:
    """
    Main runtime proxy entry point (Phase 4 Proxy + Phase 5 Policy Engine + Phase 6 Audit + Phase 7 Behavioral Anomaly Detector + Phase 0.4 Multi-Agent Governance):
    1. Normalizes incoming raw tool call request into a SecurityEvent model.
    2. Validates agent lifecycle status and multi-agent delegation scope (if invoked under delegation).
    3. Evaluates the SecurityEvent through the Phase 5 RBAC/ABAC PolicyEngine.
    4. Runs Phase 7 Behavioral Anomaly Detector to analyze session features & apply behavioral escalations.
    5. Calculates interception & analysis latency.
    6. Records the event, multi-agent provenance, and anomaly output in PostgreSQL audit storage.
    7. Returns structured InterceptorResponse verdict.
    
    SECURITY GUARANTEE: Fails closed on any unexpected exception, refusing tool execution.
    """
    start_time = time.perf_counter()

    try:
        # Step 1: Normalize payload into Phase 3A SecurityEvent
        security_event = normalize_tool_call_request(request)

        # Step 1.5: Multi-Agent Lifecycle & Delegation Governance Checks (Phase 0.4)
        agent = default_agent_registry.get_agent(request.agent_id, db)
        if agent and agent.status.value == "REVOKED":
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            apply_decision(
                security_event,
                policy_result=PolicyResult.DENY,
                reason=f"BLOCKED: Agent '{request.agent_id}' is REVOKED in AgentSentinel registry.",
            )
            enrich_event_security(
                security_event,
                sensitivity_level=SensitivityLevel.CRITICAL,
                policy_tags=["revoked_agent_block"],
                threat_flags=["REVOKED_AGENT_BLOCKED"],
            )
            security_event.execution_context.latency_ms = latency_ms
            db_record = record_audit_entry(db, security_event)
            return InterceptorResponse(
                event_id=security_event.identity.event_id,
                decision="BLOCK",
                decision_reason=security_event.decision_context.decision_reason,
                approval_required=False,
                execution_allowed=False,
                latency_ms=latency_ms,
                stored=db_record is not None,
                trace_id=security_event.audit_context.trace_id,
                timestamp=security_event.task_context.timestamp,
            )

        # If invoked under delegation token, validate delegation scope and provenance
        if request.delegation_id:
            del_valid, del_reason, delegation_ctx = default_delegation_manager.validate_delegated_tool_call(
                delegation_id=request.delegation_id,
                executing_agent_id=request.agent_id,
                tool_name=request.tool_name,
                target_resource=request.target_resource or "",
                db=db,
            )
            if not del_valid:
                latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
                apply_decision(
                    security_event,
                    policy_result=PolicyResult.DENY,
                    reason=f"BLOCKED: {del_reason}",
                )
                enrich_event_security(
                    security_event,
                    sensitivity_level=SensitivityLevel.CRITICAL,
                    policy_tags=["delegation_violation_block"],
                    threat_flags=["UNAUTHORIZED_DELEGATED_ACTION"],
                )
                if not security_event.audit_context.metadata:
                    security_event.audit_context.metadata = {}
                security_event.audit_context.metadata["multi_agent"] = {
                    "delegation_id": request.delegation_id,
                    "executing_agent_id": request.agent_id,
                    "delegation_authorized": False,
                    "violation_reason": del_reason,
                }
                security_event.execution_context.latency_ms = latency_ms
                db_record = record_audit_entry(db, security_event)
                return InterceptorResponse(
                    event_id=security_event.identity.event_id,
                    decision="BLOCK",
                    decision_reason=security_event.decision_context.decision_reason,
                    approval_required=False,
                    execution_allowed=False,
                    latency_ms=latency_ms,
                    stored=db_record is not None,
                    trace_id=security_event.audit_context.trace_id,
                    timestamp=security_event.task_context.timestamp,
                )

            # Valid delegation: attach provenance into audit metadata
            if not security_event.audit_context.metadata:
                security_event.audit_context.metadata = {}
            security_event.audit_context.metadata["multi_agent"] = {
                "delegation_id": delegation_ctx.delegation_id,
                "source_agent_id": delegation_ctx.source_agent_id,
                "target_agent_id": delegation_ctx.target_agent_id,
                "delegation_depth": delegation_ctx.delegation_depth,
                "delegated_capabilities": [c.value for c in delegation_ctx.delegated_capabilities],
                "provenance_chain": delegation_ctx.provenance_chain,
                "origin_agent_id": delegation_ctx.provenance_chain[0] if delegation_ctx.provenance_chain else delegation_ctx.source_agent_id,
            }

        # Step 2: Evaluate static policy through Phase 5 PolicyEngine
        policy_result = default_policy_engine.evaluate(security_event)

        # Step 3: Run Phase 7 Behavioral Anomaly Detector on session history
        anomaly_result = default_anomaly_detector.analyze_session(db, request.session_id, security_event)

        # Step 4: Measure total interception & detection latency
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        security_event.execution_context.latency_ms = latency_ms

        # Step 5: Record audit log entry and provision approval request in PostgreSQL (Phase 6 Service)
        db_record = record_audit_entry(db, security_event)

        # Determine final verdict (which may have been escalated by behavioral anomaly detector)
        final_verdict = security_event.decision_context.policy_result.value
        decision_str = "BLOCK" if final_verdict == "DENY" else final_verdict

        # Step 6: Observability metrics & Security alert integration
        try:
            from app.observability.metrics import metrics_registry
            metrics_registry.tool_calls_total.inc(verdict=decision_str)
            if decision_str == "BLOCK":
                from app.alerts.service import alert_engine
                alert_engine.check_and_alert_policy_block(
                    event_id=security_event.identity.event_id,
                    agent_id=security_event.identity.agent_id,
                    tool_name=security_event.tool_context.tool_name,
                    policy_name=security_event.decision_context.decision_reason or "SECURITY_POLICY",
                    db=db,
                )
            if anomaly_result and anomaly_result.is_anomalous:
                from app.alerts.service import alert_engine
                alert_engine.check_and_alert_critical_anomaly(
                    event_id=security_event.identity.event_id,
                    agent_id=security_event.identity.agent_id,
                    anomaly_score=anomaly_result.anomaly_score,
                    level=anomaly_result.anomaly_level.value,
                    db=db,
                )
        except Exception as e:
            logger.debug(f"Observability hook notice: {e}")

        return InterceptorResponse(
            event_id=security_event.identity.event_id,
            decision=decision_str,
            decision_reason=security_event.decision_context.decision_reason,
            approval_required=security_event.decision_context.approval_required,
            execution_allowed=security_event.execution_context.execution_allowed,
            latency_ms=latency_ms,
            stored=db_record is not None,
            trace_id=security_event.audit_context.trace_id,
            timestamp=security_event.task_context.timestamp,
        )
    except Exception as exc:
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        logger.error(f"Unexpected error during tool call interception: {exc}", exc_info=True)
        # Fail closed: never permit tool execution on error
        fallback_event_id = f"evt_err_{uuid.uuid4().hex[:8]}"
        return InterceptorResponse(
            event_id=fallback_event_id,
            decision="BLOCK",
            decision_reason="Security control plane encounter: action blocked by fail-closed policy.",
            approval_required=False,
            execution_allowed=False,
            latency_ms=latency_ms,
            stored=False,
            trace_id=f"trc_err_{uuid.uuid4().hex[:8]}",
        )
