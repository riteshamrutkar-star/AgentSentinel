import time
from typing import Optional
from sqlalchemy.orm import Session

from app.anomaly.detector import default_anomaly_detector
from app.audit.service import record_audit_entry
from app.interceptor.normalizer import normalize_tool_call_request
from app.interceptor.schema import InterceptorResponse, ToolCallRequest
from app.policy.engine import default_policy_engine

def intercept_tool_call(request: ToolCallRequest, db: Session) -> InterceptorResponse:
    """
    Main runtime proxy entry point (Phase 4 Proxy + Phase 5 Policy Engine + Phase 6 Audit + Phase 7 Behavioral Anomaly Detector):
    1. Normalizes incoming raw tool call request into a SecurityEvent model.
    2. Evaluates the SecurityEvent through the Phase 5 RBAC/ABAC PolicyEngine.
    3. Runs Phase 7 Behavioral Anomaly Detector to analyze session features & apply behavioral escalations.
    4. Calculates interception & analysis latency.
    5. Records the event and anomaly output in PostgreSQL audit storage.
    6. Returns structured InterceptorResponse verdict.
    """
    start_time = time.perf_counter()

    # Step 1: Normalize payload into Phase 3A SecurityEvent
    security_event = normalize_tool_call_request(request)

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
