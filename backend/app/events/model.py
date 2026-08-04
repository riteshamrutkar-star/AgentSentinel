import json
import uuid
from typing import Any, Dict, List, Optional

from app.events.schema import (
    ActionType,
    ApprovalStatus,
    AuditContext,
    DecisionContext,
    ExecutionContext,
    ExecutionStage,
    IdentityContext,
    PolicyResult,
    SecurityContext,
    SecurityEventSchema,
    SensitivityLevel,
    TaskContext,
    ToolActionContext,
)

class SecurityEvent:
    """
    Internal domain model for an intercepted AI Agent tool execution security event.
    Provides clear lifecycle methods for enrichment, policy decisioning, and auditing.
    """

    def __init__(
        self,
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
        event_id: Optional[str] = None,
    ):
        event_uuid = event_id or f"evt_{uuid.uuid4().hex[:12]}"
        
        self.identity = IdentityContext(
            event_id=event_uuid,
            session_id=session_id,
            agent_id=agent_id,
            user_id=user_id,
            role=role,
            framework_name=framework_name,
        )

        self.task_context = TaskContext(
            task_summary=task_summary,
            prompt_context_summary=prompt_context_summary,
        )

        self.tool_action = ToolActionContext(
            tool_name=tool_name,
            action_type=action_type,
            target_resource=target_resource,
            arguments_payload=arguments_payload,
        )

        self.security_context = SecurityContext()
        self.decision_context = DecisionContext()
        self.execution_context = ExecutionContext()
        self.audit_context = AuditContext(
            trace_id=f"trc_{uuid.uuid4().hex[:8]}",
            correlation_id=session_id,
        )

    def enrich_security(
        self,
        sensitivity_level: SensitivityLevel = SensitivityLevel.LOW,
        policy_tags: Optional[List[str]] = None,
        risk_indicators: Optional[List[str]] = None,
        anomaly_score: float = 0.0,
        threat_flags: Optional[List[str]] = None,
        permission_level: str = "USER",
    ) -> "SecurityEvent":
        """Enriches the event with security metadata, risk scores, and threat indicators."""
        self.security_context.sensitivity_level = sensitivity_level
        self.security_context.permission_level = permission_level
        self.security_context.anomaly_score = anomaly_score
        
        if policy_tags:
            self.security_context.policy_tags.extend(policy_tags)
        if risk_indicators:
            self.security_context.risk_indicators.extend(risk_indicators)
        if threat_flags:
            self.security_context.threat_flags.extend(threat_flags)
            
        return self

    def record_decision(
        self,
        policy_result: PolicyResult,
        decision_reason: str,
        approval_required: bool = False,
        approval_status: ApprovalStatus = ApprovalStatus.NOT_REQUIRED,
        reviewer: Optional[str] = None,
    ) -> "SecurityEvent":
        """Records the outcome of policy engine evaluation."""
        self.decision_context.policy_result = policy_result
        self.decision_context.decision_result = policy_result.value
        self.decision_context.decision_reason = decision_reason
        self.decision_context.approval_required = approval_required
        self.decision_context.approval_status = approval_status
        self.decision_context.reviewer = reviewer

        # Update execution permission status based on policy verdict
        self.execution_context.execution_allowed = policy_result in (PolicyResult.ALLOW, PolicyResult.FLAG_ONLY)
        
        if policy_result == PolicyResult.DENY:
            self.tool_action.execution_stage = ExecutionStage.TERMINATED
            
        return self

    def record_execution(
        self,
        result_payload: Optional[Dict[str, Any]] = None,
        latency_ms: float = 0.0,
        error_message: Optional[str] = None,
    ) -> "SecurityEvent":
        """Records the tool execution response metrics and latency."""
        self.execution_context.execution_result = result_payload
        self.execution_context.latency_ms = latency_ms
        self.execution_context.error_message = error_message
        self.tool_action.execution_stage = ExecutionStage.POST_EXECUTION
        return self

    def to_schema(self) -> SecurityEventSchema:
        """Converts the domain model instance to a typed Pydantic Schema."""
        return SecurityEventSchema(
            identity=self.identity,
            task_context=self.task_context,
            tool_action=self.tool_action,
            security_context=self.security_context,
            decision_context=self.decision_context,
            execution_context=self.execution_context,
            audit_context=self.audit_context,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serializes event to a clean Python dictionary."""
        return self.to_schema().model_dump()

    def to_json(self, indent: int = 2) -> str:
        """Serializes event to a formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def __repr__(self) -> str:
        return (
            f"<SecurityEvent id='{self.identity.event_id}' "
            f"agent='{self.identity.agent_id}' tool='{self.tool_action.tool_name}' "
            f"decision='{self.decision_context.decision_result}'>"
        )
