from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class ScenarioResult(BaseModel):
    """Execution metrics for a single evaluation scenario."""
    scenario_id: str = Field(..., description="Unique scenario identifier")
    scenario_name: str = Field(..., description="Human-readable scenario title")
    role: str = Field(..., description="Assigned agent role")
    tool_name: str = Field(..., description="Intercepted tool name")
    action_type: str = Field(..., description="Action category (NETWORK, READ, WRITE, DATABASE)")
    target_resource: str = Field(..., description="Target resource string")
    policy_result: str = Field(..., description="Policy Engine verdict (ALLOW, DENY, REQUIRE_APPROVAL)")
    anomaly_score: float = Field(..., description="Calculated behavioral anomaly score (0.0 - 1.0)")
    anomaly_level: str = Field(..., description="Anomaly level (LOW, MEDIUM, HIGH, CRITICAL)")
    final_decision: str = Field(..., description="Final interceptor decision (ALLOW, BLOCK, REQUIRE_APPROVAL)")
    execution_allowed: bool = Field(..., description="True if tool execution was permitted")
    approval_required: bool = Field(..., description="True if human approval was requested")
    approval_status: Optional[str] = Field(None, description="Approval status (PENDING, APPROVED, REJECTED, N/A)")
    latency_ms: float = Field(..., description="Interception processing latency in milliseconds")
    db_persisted: bool = Field(True, description="True if security event was saved in PostgreSQL")
    dashboard_visible: bool = Field(True, description="True if visible via dashboard APIs")
    passed: bool = Field(True, description="True if outcome matched security expectations")

class EvaluationMetricsSummary(BaseModel):
    """Aggregated evaluation metrics for the AgentSentinel prototype."""
    total_scenarios: int = Field(0, description="Total benchmark scenarios evaluated")
    allowed_count: int = Field(0, description="Count of allowed actions")
    blocked_count: int = Field(0, description="Count of blocked actions")
    approval_required_count: int = Field(0, description="Count of approval-required actions")
    approved_count: int = Field(0, description="Count of approved human reviews")
    rejected_count: int = Field(0, description="Count of rejected human reviews")
    min_anomaly_score: float = Field(0.0, description="Minimum observed anomaly score")
    max_anomaly_score: float = Field(0.0, description="Maximum observed anomaly score")
    avg_anomaly_score: float = Field(0.0, description="Average anomaly score")
    avg_latency_ms: float = Field(0.0, description="Average interception latency in ms")
    total_audit_records: int = Field(0, description="Total PostgreSQL audit records created")
    total_approval_records: int = Field(0, description="Total PostgreSQL approval records created")
    pipeline_success_rate: float = Field(100.0, description="Pipeline end-to-end success percentage")
