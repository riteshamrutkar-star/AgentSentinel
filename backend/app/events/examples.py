from app.events.factory import apply_decision, create_security_event, enrich_event_security
from app.events.model import SecurityEvent
from app.events.schema import ActionType, PolicyResult, SensitivityLevel

def get_benign_event_example() -> SecurityEvent:
    """Returns a realistic benign security event example (Web Search / Read-only action)."""
    event = create_security_event(
        session_id="sess_benign_9921",
        agent_id="agent_researcher_01",
        user_id="usr_alice_402",
        tool_name="google_search",
        action_type=ActionType.NETWORK,
        target_resource="https://api.search.google.com/v1",
        arguments_payload={"query": "FastAPI security best practices 2026", "max_results": 5},
        role="research_assistant",
        framework_name="LangChain",
        task_summary="Summarize modern API security trends for research document",
        prompt_context_summary="User asked: 'Find recent security guidelines for building REST APIs.'",
    )

    enrich_event_security(
        event,
        sensitivity_level=SensitivityLevel.LOW,
        policy_tags=["web_search", "read_only", "external_api"],
        risk_indicators=[],
        anomaly_score=0.02,
        threat_flags=[],
        permission_level="PUBLIC_READ",
    )

    apply_decision(
        event,
        policy_result=PolicyResult.ALLOW,
        reason="Action is read-only and targets an approved external search domain.",
    )

    event.record_execution(
        result_payload={"items_returned": 5, "status_code": 200},
        latency_ms=142.5,
    )

    return event

def get_suspicious_event_example() -> SecurityEvent:
    """Returns a realistic suspicious security event example (Attempted SSH key / exfiltration access)."""
    event = create_security_event(
        session_id="sess_attack_3301",
        agent_id="agent_coder_bot",
        user_id="usr_bob_881",
        tool_name="read_system_file",
        action_type=ActionType.READ,
        target_resource="/home/user/.ssh/id_rsa",
        arguments_payload={"filepath": "/home/user/.ssh/id_rsa", "encoding": "utf-8"},
        role="code_assistant",
        framework_name="AutoGen",
        task_summary="Debug application server deployment configuration",
        prompt_context_summary="User requested code optimization. Unexpected prompt injection payload detected in input file.",
    )

    enrich_event_security(
        event,
        sensitivity_level=SensitivityLevel.CRITICAL,
        policy_tags=["file_system", "credential_access", "sensitive_file"],
        risk_indicators=[
            "UNAUTHORIZED_CREDENTIAL_PATH",
            "PRIVILEGED_FILE_READ",
            "PROMPT_INJECTION_SUSPICION"
        ],
        anomaly_score=0.94,
        threat_flags=["CREDENTIAL_EXFILTRATION_ATTEMPT", "PATH_TRAVERSAL"],
        permission_level="SYSTEM_ADMIN",
    )

    apply_decision(
        event,
        policy_result=PolicyResult.DENY,
        reason="BLOCKED: Tool invocation attempts to read private SSH keys without authorization.",
    )

    event.record_execution(
        result_payload=None,
        latency_ms=4.2,
        error_message="SecurityPolicyViolation: Access to sensitive file path prohibited.",
    )

    return event
