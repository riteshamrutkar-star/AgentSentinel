"""
Tool Transition Detector for AgentSentinel.
Evaluates pairwise transitions between consecutively executed tools against
a calibrated risk transition matrix to identify anomalous workflow shifts.
"""

from typing import Any, Dict, List, Optional
from app.anomaly.base import BehavioralDetector, DetectorResult
from app.anomaly.config import behavioral_config
from app.events.model import SecurityEvent

class ToolTransitionDetector(BehavioralDetector):
    """
    Evaluates tool-to-tool transitions using a weighted transition risk matrix:
    - High-risk shifts (e.g. read_system_file -> write_workspace_file or network)
    - Medium-risk shifts (e.g. search -> drop_database_table)
    - Routine standard shifts (e.g. search -> read_workspace_file)
    """

    @property
    def name(self) -> str:
        return "ToolTransitionDetector"

    @property
    def weight(self) -> float:
        return behavioral_config.WEIGHT_TOOL_TRANSITION

    @property
    def description(self) -> str:
        return "Evaluates tool-to-tool transitions against a weighted security risk matrix to detect unexpected workflow hops."

    def detect(
        self,
        event: SecurityEvent,
        history: List[Any],
        context: Optional[Dict[str, Any]] = None
    ) -> DetectorResult:
        ctx = context or {}
        features = ctx.get("features", {})
        transition_pair = features.get("transition_pair")
        curr_tool = event.tool_action.tool_name.lower().strip()
        prev_tool = features.get("previous_tool")

        score = 0.05
        evidence: List[str] = []

        if not prev_tool:
            # First tool in session: no transition risk
            return DetectorResult.create(
                detector_name=self.name,
                score=0.05,
                explanation=f"Initial session tool invocation '{curr_tool}'; no prior transition to evaluate.",
                confidence=0.50,
                metadata={"transition_pair": None, "transition_risk": 0.05},
            )

        pair = (prev_tool, curr_tool)

        # Check explicit transition risk map
        if pair in behavioral_config.TRANSITION_RISK_MAP:
            transition_risk = behavioral_config.TRANSITION_RISK_MAP[pair]
        else:
            # Fallback heuristic: check if crossing action type domains
            action_types = features.get("action_types", [])
            if len(action_types) >= 2 and action_types[-2] != action_types[-1]:
                transition_risk = behavioral_config.DEFAULT_TRANSITION_RISK_CROSS_DOMAIN
            else:
                transition_risk = behavioral_config.DEFAULT_TRANSITION_RISK_SAME_DOMAIN

        score = max(score, transition_risk)

        if transition_risk >= 0.70:
            evidence.append(f"High-risk transition detected: '{prev_tool}' -> '{curr_tool}' (risk weight: {transition_risk:.2f})")
            explanation = f"Critical tool transition anomaly: workflow hopped from '{prev_tool}' to high-risk '{curr_tool}'."
        elif transition_risk >= 0.35:
            evidence.append(f"Uncommon transition detected: '{prev_tool}' -> '{curr_tool}' (risk weight: {transition_risk:.2f})")
            explanation = f"Uncommon workflow transition from '{prev_tool}' to '{curr_tool}'."
        else:
            explanation = f"Tool transition '{prev_tool}' -> '{curr_tool}' aligns with standard development/research patterns."

        confidence = 0.85

        return DetectorResult.create(
            detector_name=self.name,
            score=round(score, 3),
            explanation=explanation,
            evidence=evidence,
            confidence=confidence,
            metadata={"transition_pair": f"{prev_tool} -> {curr_tool}", "transition_risk": transition_risk},
        )
