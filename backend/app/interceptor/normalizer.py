from typing import Union
from app.events.factory import create_security_event
from app.events.model import SecurityEvent
from app.events.schema import ActionType
from app.interceptor.schema import ToolCallRequest
from app.core.canonical import CanonicalSecurityRequest, from_tool_call_request


def normalize_canonical_request(request: CanonicalSecurityRequest) -> SecurityEvent:
    """
    Normalizes a unified CanonicalSecurityRequest into a fully typed
    SecurityEvent domain model for policy engine evaluation and audit persistence.
    """
    action_type_enum = ActionType.UNKNOWN
    if request.action_type:
        normalized_act = request.action_type.strip().upper()
        if normalized_act in ActionType.__members__:
            action_type_enum = ActionType[normalized_act]

    security_event = create_security_event(
        session_id=request.session_id,
        agent_id=request.agent_id,
        user_id=request.user_id,
        tool_name=request.tool_name,
        arguments_payload=request.arguments,
        role=request.role or "default_agent",
        framework_name=request.framework_name or "REST",
        target_resource=request.target_resource or "",
        action_type=action_type_enum,
        task_summary=request.task_summary or "",
        prompt_context_summary=request.prompt_context_summary or "",
        namespace=request.namespace or "default",
    )

    if request.delegation_id:
        if not security_event.audit_context.metadata:
            security_event.audit_context.metadata = {}
        security_event.audit_context.metadata["delegation_id"] = request.delegation_id

    return security_event


def normalize_tool_call_request(request: Union[ToolCallRequest, CanonicalSecurityRequest]) -> SecurityEvent:
    """
    Normalizes a raw incoming ToolCallRequest (or CanonicalSecurityRequest)
    into a fully typed SecurityEvent domain model.
    """
    if isinstance(request, CanonicalSecurityRequest):
        return normalize_canonical_request(request)
    canonical = from_tool_call_request(request)
    return normalize_canonical_request(canonical)

