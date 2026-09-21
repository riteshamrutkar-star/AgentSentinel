import time
import uuid
from typing import Optional
from sqlalchemy.orm import Session

from app.anomaly.detector import default_anomaly_detector
from app.audit.service import record_audit_entry
from app.core.canonical import (
    CanonicalActionType,
    CanonicalSecurityDecision,
    CanonicalSecurityRequest,
    CanonicalVerdict,
    canonical_decision_to_interceptor_response,
    from_tool_call_request,
)
from app.core.logger import logger
from app.events.factory import apply_decision, enrich_event_security
from app.events.schema import PolicyResult, SensitivityLevel
from app.interceptor.normalizer import normalize_canonical_request, normalize_tool_call_request
from app.interceptor.schema import InterceptorResponse, ToolCallRequest
from app.multiagent.delegation import default_delegation_manager
from app.multiagent.registry import default_agent_registry
from app.policy.engine import default_policy_engine


def evaluate_canonical_request(request: CanonicalSecurityRequest, db: Session) -> CanonicalSecurityDecision:
    """
    Authoritative v1.0 security pipeline evaluation.
    Enforces deterministic architectural precedence:
    1. Agent lifecycle status (REVOKED agent -> DENY)
    2. Delegation scope validation (invalid delegation -> DENY)
    3. Static RBAC/ABAC policy engine evaluation (explicit DENY is irrevocable)
    4. Behavioral anomaly detection (can escalate ALLOW -> REQUIRE_APPROVAL or DENY; cannot weaken DENY)
    5. Persistence & Transactional Outbox (commits event and queues outbox)
    6. Observability & Alerting
    7. Fail-closed error handling on unexpected failure
    """
    start_time = time.perf_counter()

    try:
        # Step 1: Normalize request into SecurityEvent domain model
        security_event = normalize_tool_call_request(request)

        # Step 1.5: Multi-Agent Lifecycle & Delegation Governance Checks
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
            record_audit_entry(db, security_event)
            return CanonicalSecurityDecision(
                verdict=CanonicalVerdict.DENY,
                decision_reason=security_event.decision_context.decision_reason,
                policy_name="REVOKED_AGENT_BLOCK",
                approval_required=False,
                execution_allowed=False,
                threat_flags=["REVOKED_AGENT_BLOCKED"],
                namespace=request.namespace,
                event_id=security_event.identity.event_id,
                trace_id=security_event.audit_context.trace_id,
                request_id=request.request_id,
                correlation_id=request.correlation_id,
                latency_ms=latency_ms,
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
                record_audit_entry(db, security_event)
                return CanonicalSecurityDecision(
                    verdict=CanonicalVerdict.DENY,
                    decision_reason=security_event.decision_context.decision_reason,
                    policy_name="DELEGATION_SCOPE_VIOLATION",
                    approval_required=False,
                    execution_allowed=False,
                    threat_flags=["UNAUTHORIZED_DELEGATED_ACTION"],
                    namespace=request.namespace,
                    event_id=security_event.identity.event_id,
                    trace_id=security_event.audit_context.trace_id,
                    request_id=request.request_id,
                    correlation_id=request.correlation_id,
                    latency_ms=latency_ms,
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

        # Step 2: Evaluate static policy through PolicyEngine
        policy_result = default_policy_engine.evaluate(security_event)

        # Step 3: Run Behavioral Anomaly Detector on session history
        anomaly_result = default_anomaly_detector.analyze_session(db, request.session_id, security_event)

        # DETERMINISTIC PRECEDENCE ENFORCEMENT:
        # If static policy returned DENY, behavioral analysis cannot weaken it.
        # If static policy returned ALLOW and anomaly detector found high risk, behavioral detector escalates.
        if policy_result == PolicyResult.DENY:
            security_event.decision_context.policy_result = PolicyResult.DENY
            security_event.execution_context.execution_allowed = False

        # Step 4: Measure total interception & detection latency
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        security_event.execution_context.latency_ms = latency_ms

        # Step 5: Record audit log entry and provision approval request in PostgreSQL
        record_audit_entry(db, security_event)

        # Map to CanonicalVerdict
        final_policy_res = security_event.decision_context.policy_result
        if final_policy_res == PolicyResult.DENY:
            verdict = CanonicalVerdict.DENY
        elif final_policy_res == PolicyResult.REQUIRE_APPROVAL:
            verdict = CanonicalVerdict.REQUIRE_APPROVAL
        else:
            verdict = CanonicalVerdict.ALLOW

        decision_str = "BLOCK" if verdict == CanonicalVerdict.DENY else verdict.value

        # Step 6: Observability metrics & Security alert integration
        try:
            from app.observability.metrics import metrics_registry
            metrics_registry.tool_calls_total.inc(verdict=decision_str)
            if verdict == CanonicalVerdict.DENY:
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

        # Provenance chain extraction
        prov_chain = []
        if security_event.audit_context.metadata and "multi_agent" in security_event.audit_context.metadata:
            prov_chain = security_event.audit_context.metadata["multi_agent"].get("provenance_chain", [])

        return CanonicalSecurityDecision(
            verdict=verdict,
            decision_reason=security_event.decision_context.decision_reason,
            policy_name="SECURITY_POLICY",
            risk_score=getattr(security_event.security_context, "anomaly_score", 0.0) or 0.0,
            anomaly_level=anomaly_result.anomaly_level.value if anomaly_result else "NORMAL",
            approval_required=security_event.decision_context.approval_required,
            execution_allowed=security_event.execution_context.execution_allowed,
            threat_flags=security_event.security_context.threat_flags,
            policy_tags=security_event.security_context.policy_tags,
            risk_indicators=security_event.security_context.risk_indicators,
            provenance_chain=prov_chain,
            namespace=request.namespace,
            event_id=security_event.identity.event_id,
            trace_id=security_event.audit_context.trace_id,
            request_id=request.request_id,
            correlation_id=request.correlation_id,
            latency_ms=latency_ms,
        )

    except Exception as exc:
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        logger.error(f"Unexpected error during canonical security evaluation: {exc}", exc_info=True)
        # Fail closed: never permit tool execution on error
        err_id = f"evt_err_{uuid.uuid4().hex[:8]}"
        return CanonicalSecurityDecision(
            verdict=CanonicalVerdict.ERROR,
            decision_reason="Security control plane encounter: action blocked by fail-closed policy.",
            policy_name="FAIL_CLOSED_ERROR",
            approval_required=False,
            execution_allowed=False,
            threat_flags=["SYSTEM_ERROR_FAIL_CLOSED"],
            namespace=request.namespace,
            event_id=err_id,
            trace_id=f"trc_err_{uuid.uuid4().hex[:8]}",
            request_id=request.request_id,
            correlation_id=request.correlation_id,
            latency_ms=latency_ms,
        )


def intercept_tool_call(request: ToolCallRequest, db: Session) -> InterceptorResponse:
    """
    Main runtime proxy entry point.
    Normalizes incoming ToolCallRequest into CanonicalSecurityRequest,
    delegates to evaluate_canonical_request, and returns an InterceptorResponse.
    """
    canonical_req = from_tool_call_request(request)
    decision = evaluate_canonical_request(canonical_req, db=db)
    return canonical_decision_to_interceptor_response(decision, stored=True)

