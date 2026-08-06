from app.events.factory import create_security_event
from app.events.model import SecurityEvent
from app.events.schema import ActionType
from app.interceptor.schema import ToolCallRequest

def normalize_tool_call_request(request: ToolCallRequest) -> SecurityEvent:
    """
    Normalizes a raw incoming ToolCallRequest from an AI agent or wrapper into
    a fully typed Phase 3A SecurityEvent domain model.
    """
    # Map string action_type to ActionType enum safely
    action_type_enum = ActionType.UNKNOWN
    if request.action_type:
        normalized_act = request.action_type.strip().upper()
        if normalized_act in ActionType.__members__:
            action_type_enum = ActionType[normalized_act]

    # Ingest raw request attributes into SecurityEvent factory
    security_event = create_security_event(
        session_id=request.session_id,
        agent_id=request.agent_id,
        user_id=request.user_id,
        tool_name=request.tool_name,
        arguments_payload=request.arguments,
        role=request.role or "default_agent",
        framework_name=request.framework_name or "LangChain",
        target_resource=request.target_resource or "",
        action_type=action_type_enum,
        task_summary=request.task_summary or "",
        prompt_context_summary=request.prompt_context_summary or "",
    )

    return security_event
