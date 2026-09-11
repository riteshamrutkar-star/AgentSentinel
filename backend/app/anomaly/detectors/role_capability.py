"""
Role and Capability Mismatch Detector for AgentSentinel.
Identifies agent tool invocations that deviate from an agent's assigned role,
expected capability boundary, and principle of least privilege.
"""

from typing import Any, Dict, List, Optional
from app.anomaly.base import BehavioralDetector, DetectorResult
from app.anomaly.config import behavioral_config
from app.events.model import SecurityEvent

class RoleCapabilityMismatchDetector(BehavioralDetector):
    """
    Evaluates tool actions against assigned agent roles:
    - Research assistants invoking destructive DB or write tools
    - Code assistants attempting schema drop operations
    - Default or guest agents touching sensitive administrative files
    """

    @property
    def name(self) -> str:
        return "RoleCapabilityMismatchDetector"

    @property
    def weight(self) -> float:
        return behavioral_config.WEIGHT_ROLE_MISMATCH

    @property
    def description(self) -> str:
        return "Flags tool invocations and action types that exceed or conflict with assigned agent role capability scopes."

    def detect(
        self,
        event: SecurityEvent,
        history: List[Any],
        context: Optional[Dict[str, Any]] = None
    ) -> DetectorResult:
        ctx = context or {}
        features = ctx.get("features", {})
        curr_role = event.identity.role.lower().strip()
        curr_tool = event.tool_action.tool_name.lower().strip()
        curr_action_type = (
            event.tool_action.action_type.value
            if hasattr(event.tool_action.action_type, "value")
            else str(event.tool_action.action_type).upper()
        )

        score = 0.05
        evidence: List[str] = []
        is_mismatch = False

        # Check 1: Explicit prohibited tools list for this role
        prohibited_tools = behavioral_config.ROLE_PROHIBITED_TOOLS.get(curr_role, [])
        if curr_tool in prohibited_tools or any(p in curr_tool for p in prohibited_tools):
            score = max(score, 0.85)
            is_mismatch = True
            evidence.append(f"Explicit role violation: Tool '{curr_tool}' is prohibited for role '{curr_role}'")

        # Check 2: Action type capability scope
        allowed_scopes = behavioral_config.ROLE_CAPABILITY_SCOPES.get(curr_role, {"READ", "NETWORK"})
        if curr_action_type not in allowed_scopes and curr_action_type != "UNKNOWN":
            score = max(score, 0.70)
            is_mismatch = True
            evidence.append(f"Action capability mismatch: Action type '{curr_action_type}' is outside permitted scopes {allowed_scopes} for role '{curr_role}'")

        # Check 3: Destructive database tool called by non-dba role
        if ("drop" in curr_tool or curr_action_type == "DATABASE") and curr_role != "database_admin" and curr_role != "system_admin":
            score = max(score, 0.90)
            is_mismatch = True
            evidence.append(f"Privilege overreach: Non-DBA role '{curr_role}' attempted administrative database action '{curr_tool}'")

        clamped_score = min(1.0, max(0.0, score))
        confidence = 0.90 if is_mismatch else 0.70

        if is_mismatch:
            explanation = f"Role/Capability mismatch detected: {'; '.join(evidence)}"
        else:
            explanation = f"Tool '{curr_tool}' ({curr_action_type}) is compatible with assigned role '{curr_role}'."

        return DetectorResult.create(
            detector_name=self.name,
            score=clamped_score,
            explanation=explanation,
            evidence=evidence,
            confidence=confidence,
            metadata={"role": curr_role, "tool": curr_tool, "action_type": curr_action_type},
        )
