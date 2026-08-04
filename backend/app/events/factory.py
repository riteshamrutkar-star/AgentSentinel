from typing import Any, Dict, List, Optional
from app.events.model import SecurityEvent
from app.events.schema import ActionType, ApprovalStatus, PolicyResult, SensitivityLevel

def create_security_event(
    session_id: str,
    agent_id: str,
    user_id: str,
    tool_name: str,
    arguments_payload: Dict[str, Any],
    role: str = "default_agent",
    framework_name: str = "LangChain",
    target_resource: str = "",
    action_type: ActionType = ActionType.UNKNOWN,
    task_summary: str = "",
    prompt_context_summary: str = "",
) -> SecurityEvent:
    """Instantiates a new raw SecurityEvent from intercepted tool call arguments."""
    return SecurityEvent(
        session_id=session_id,
        agent_id=agent_id,
        user_id=user_id,
        tool_name=tool_name,
        arguments_payload=arguments_payload,
        role=role,
        framework_name=framework_name,
        target_resource=target_resource,
        action_type=action_type,
        task_summary=task_summary,
        prompt_context_summary=prompt_context_summary,
    )

def enrich_event_security(
    event: SecurityEvent,
    sensitivity_level: SensitivityLevel = SensitivityLevel.LOW,
    policy_tags: Optional[List[str]] = None,
    risk_indicators: Optional[List[str]] = None,
    anomaly_score: float = 0.0,
    threat_flags: Optional[List[str]] = None,
    permission_level: str = "USER",
) -> SecurityEvent:
    """Enriches an existing security event with evaluated risk parameters."""
    return event.enrich_security(
        sensitivity_level=sensitivity_level,
        policy_tags=policy_tags,
        risk_indicators=risk_indicators,
        anomaly_score=anomaly_score,
        threat_flags=threat_flags,
        permission_level=permission_level,
    )

def apply_decision(
    event: SecurityEvent,
    policy_result: PolicyResult,
    reason: str,
    approval_required: bool = False,
    approval_status: ApprovalStatus = ApprovalStatus.NOT_REQUIRED,
    reviewer: Optional[str] = None,
) -> SecurityEvent:
    """Applies a security policy decision to the event."""
    return event.record_decision(
        policy_result=policy_result,
        decision_reason=reason,
        approval_required=approval_required,
        approval_status=approval_status,
        reviewer=reviewer,
    )
