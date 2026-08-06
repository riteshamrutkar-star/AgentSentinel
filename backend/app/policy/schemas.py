from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class RuleType(str, Enum):
    RBAC = "RBAC"
    ABAC = "ABAC"
    SECURITY = "SECURITY"

class RuleEffect(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"

class PolicyRule(BaseModel):
    """Schema defining an RBAC, ABAC, or Security Policy Rule."""
    rule_id: str = Field(..., description="Unique rule identifier (e.g. SEC_BLOCK_CREDENTIALS)")
    rule_name: str = Field(..., description="Human-readable rule name")
    rule_type: RuleType = Field(RuleType.SECURITY, description="Rule category: RBAC, ABAC, or SECURITY")
    effect: RuleEffect = Field(RuleEffect.BLOCK, description="Policy verdict effect: ALLOW, BLOCK, or REQUIRE_APPROVAL")
    role: str = Field("*", description="Target agent/user role pattern ('*' matches any)")
    tool_name: str = Field("*", description="Target tool name pattern ('*' matches any)")
    action_type: str = Field("*", description="Target action type pattern (READ, WRITE, EXECUTE, NETWORK, DATABASE)")
    resource_pattern: str = Field("*", description="Target resource filepath or URI glob pattern")
    priority: int = Field(100, description="Evaluation priority order (lower numbers evaluate first)")
    description: str = Field("", description="Detailed explanation of the rule")
    sensitivity_level: Optional[str] = Field(None, description="Optional sensitivity threshold requirement")

class PolicyEvaluationResult(BaseModel):
    """Structured verdict returned by PolicyEngine evaluation."""
    event_id: str = Field(..., description="Associated security event UUID")
    verdict: str = Field(..., description="Final policy verdict: ALLOW, BLOCK, or REQUIRE_APPROVAL")
    decision_reason: str = Field(..., description="Human-readable decision explanation")
    matched_rule_id: Optional[str] = Field(None, description="ID of the matching policy rule")
    matched_rule_name: Optional[str] = Field(None, description="Name of the matching policy rule")
    matched_rule_type: Optional[str] = Field(None, description="Category of the matching rule (RBAC/ABAC/SECURITY)")
    risk_level: str = Field("LOW", description="Evaluated risk level (LOW, MEDIUM, HIGH, CRITICAL)")
    execution_allowed: bool = Field(True, description="True if tool execution is permitted")
    approval_required: bool = Field(False, description="True if human approval is required")
    evaluated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="ISO UTC timestamp")
