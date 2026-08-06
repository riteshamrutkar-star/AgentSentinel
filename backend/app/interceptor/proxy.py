import time
from typing import Optional
from sqlalchemy.orm import Session

from app.db.crud import save_security_event
from app.interceptor.normalizer import normalize_tool_call_request
from app.interceptor.schema import InterceptorResponse, ToolCallRequest
from app.policy.engine import default_policy_engine

def intercept_tool_call(request: ToolCallRequest, db: Session) -> InterceptorResponse:
    """
    Main runtime proxy entry point (Phase 4 Proxy + Phase 5 Policy Engine):
    1. Normalizes incoming raw tool call request into a SecurityEvent model.
    2. Evaluates the SecurityEvent through the Phase 5 RBAC/ABAC PolicyEngine.
    3. Calculates interception & policy evaluation latency.
    4. Persists the event and policy verdict into PostgreSQL.
    5. Returns structured InterceptorResponse verdict.
    """
    start_time = time.perf_counter()

    # Step 1: Normalize payload into Phase 3A SecurityEvent
    security_event = normalize_tool_call_request(request)

    # Step 2: Evaluate through Phase 5 RBAC/ABAC PolicyEngine
    policy_result = default_policy_engine.evaluate(security_event)

    # Step 3: Measure proxy latency
    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
    security_event.execution_context.latency_ms = latency_ms

    # Step 4: Persist event and policy verdict into PostgreSQL database via Phase 3B CRUD
    db_record = save_security_event(db, security_event)

    # Step 5: Format response verdict
    return InterceptorResponse(
        event_id=security_event.identity.event_id,
        decision=policy_result.verdict,
        decision_reason=policy_result.decision_reason,
        approval_required=policy_result.approval_required,
        execution_allowed=policy_result.execution_allowed,
        latency_ms=latency_ms,
        stored=db_record is not None,
        trace_id=security_event.audit_context.trace_id,
        timestamp=security_event.task_context.timestamp,
    )
