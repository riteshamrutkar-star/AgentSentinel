import time
from typing import Optional
from sqlalchemy.orm import Session

from app.db.crud import save_security_event
from app.events.factory import apply_decision, enrich_event_security
from app.events.schema import ApprovalStatus, PolicyResult, SensitivityLevel
from app.interceptor.normalizer import normalize_tool_call_request
from app.interceptor.schema import InterceptorResponse, ToolCallRequest

def evaluate_proxy_heuristics(security_event) -> None:
    """
    Simulates early security proxy heuristics & rule evaluation prior to full Phase 5 policy engine.
    Classifies risk levels, threat flags, and initial decision verdict.
    """
    tool_name = security_event.tool_action.tool_name.lower()
    target_resource = security_event.tool_action.target_resource.lower()
    args_str = str(security_event.tool_action.arguments_payload).lower()

    # Heuristic 1: Sensitive Credential / Path Traversal Access -> BLOCK
    sensitive_keywords = [".ssh", "id_rsa", "/etc/shadow", "/etc/passwd", ".env", "aws/credentials", "private_key"]
    if any(kw in target_resource or kw in args_str for kw in sensitive_keywords):
        enrich_event_security(
            security_event,
            sensitivity_level=SensitivityLevel.CRITICAL,
            policy_tags=["credential_access", "sensitive_file", "path_traversal"],
            risk_indicators=["UNAUTHORIZED_CREDENTIAL_PATH", "PRIVILEGED_FILE_READ"],
            anomaly_score=0.92,
            threat_flags=["CREDENTIAL_EXFILTRATION_ATTEMPT", "PATH_TRAVERSAL"],
            permission_level="SYSTEM_ADMIN",
        )
        apply_decision(
            security_event,
            policy_result=PolicyResult.DENY,
            reason="BLOCKED: Tool invocation targets restricted private credential files.",
        )
        return

    # Heuristic 2: Destructive Database / System Operations -> REQUIRE_APPROVAL
    destructive_keywords = ["drop_table", "drop_database", "delete_all", "rm -rf", "format_disk"]
    if any(kw in tool_name or kw in args_str for kw in destructive_keywords):
        enrich_event_security(
            security_event,
            sensitivity_level=SensitivityLevel.HIGH,
            policy_tags=["destructive_action", "database_write"],
            risk_indicators=["DESTRUCTIVE_OPERATION_ATTEMPT"],
            anomaly_score=0.85,
            threat_flags=["POTENTIAL_DATA_DESTRUCTION"],
            permission_level="ADMIN",
        )
        apply_decision(
            security_event,
            policy_result=PolicyResult.REQUIRE_APPROVAL,
            reason="REQUIRE_APPROVAL: Destructive operation requires human administrator sign-off.",
            approval_required=True,
            approval_status=ApprovalStatus.PENDING,
        )
        return

    # Heuristic 3: Benign / Standard Actions -> ALLOW
    enrich_event_security(
        security_event,
        sensitivity_level=SensitivityLevel.LOW,
        policy_tags=["standard_tool_call"],
        anomaly_score=0.03,
        permission_level="USER",
    )
    apply_decision(
        security_event,
        policy_result=PolicyResult.ALLOW,
        reason="ALLOW: Tool action passed security proxy heuristic evaluation.",
    )

def intercept_tool_call(request: ToolCallRequest, db: Session) -> InterceptorResponse:
    """
    Main runtime proxy entry point:
    1. Normalizes incoming raw tool call request into a SecurityEvent.
    2. Evaluates security rules & policy verdicts.
    3. Calculates execution latency.
    4. Persists the event into PostgreSQL.
    5. Returns structured InterceptorResponse verdict.
    """
    start_time = time.perf_counter()

    # Step 1: Normalize payload
    security_event = normalize_tool_call_request(request)

    # Step 2: Evaluate security proxy rules
    evaluate_proxy_heuristics(security_event)

    # Step 3: Measure proxy latency
    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
    security_event.execution_context.latency_ms = latency_ms

    # Step 4: Persist event into PostgreSQL database via Phase 3B CRUD
    db_record = save_security_event(db, security_event)

    # Step 5: Format response verdict
    verdict = security_event.decision_context.policy_result.value
    # Map PolicyResult to proxy verdict string (ALLOW, BLOCK, REQUIRE_APPROVAL)
    decision_str = "BLOCK" if verdict == "DENY" else verdict

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
