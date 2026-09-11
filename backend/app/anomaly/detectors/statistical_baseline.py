"""
Statistical Baseline Detector for AgentSentinel.
Preserves the proven Phase 0.2 composite statistical heuristic scoring logic
as the modular reference baseline detector.
"""

from typing import Any, Dict, List, Optional
from app.anomaly.base import BehavioralDetector, DetectorResult
from app.anomaly.config import behavioral_config
from app.events.model import SecurityEvent

class StatisticalBaselineDetector(BehavioralDetector):
    """
    Evaluates session history using the Phase 0.2 composite scoring heuristic:
    denied actions, sensitive action frequency, burst counts, and high denied ratios.
    """

    @property
    def name(self) -> str:
        return "StatisticalBaselineDetector"

    @property
    def weight(self) -> float:
        return behavioral_config.WEIGHT_STATISTICAL

    @property
    def description(self) -> str:
        return "Statistical and heuristic baseline scorer assessing denial frequency, burst rates, and sensitive keyword density."

    def detect(
        self,
        event: SecurityEvent,
        history: List[Any],
        context: Optional[Dict[str, Any]] = None
    ) -> DetectorResult:
        ctx = context or {}
        features = ctx.get("features", {})

        denied_count = float(features.get("denied_count", 0.0))
        sensitive_count = float(features.get("sensitive_action_count", 0.0))
        burst_count = float(features.get("burst_events_count", 0.0))
        ratio_denied = float(features.get("ratio_denied", 0.0))
        seq_length = max(1.0, float(features.get("sequence_length", 1.0)))

        # Baseline noise score
        score = 0.05
        evidence = []

        if denied_count >= 1:
            penalty = min(0.35, denied_count * 0.15)
            score += penalty
            evidence.append(f"Historical denied actions: {int(denied_count)} (penalty +{penalty:.2f})")

        if sensitive_count >= 1:
            penalty = min(0.35, sensitive_count * 0.15)
            score += penalty
            evidence.append(f"Sensitive resource references: {int(sensitive_count)} (penalty +{penalty:.2f})")

        if burst_count >= 2:
            penalty = min(0.20, burst_count * 0.08)
            score += penalty
            evidence.append(f"Sub-2s burst calls observed: {int(burst_count)} (penalty +{penalty:.2f})")

        if ratio_denied > 0.40 and seq_length > 2:
            score += 0.25
            evidence.append(f"High failure ratio: {ratio_denied:.1%} exceeds 40% threshold (penalty +0.25)")

        clamped_score = min(1.0, max(0.0, score))

        if not evidence:
            explanation = "Session statistics align with standard baseline activity."
        else:
            explanation = f"Statistical baseline deviations: {'; '.join(evidence)}"

        confidence = min(1.0, 0.50 + (seq_length * 0.05))

        return DetectorResult.create(
            detector_name=self.name,
            score=clamped_score,
            explanation=explanation,
            evidence=evidence,
            confidence=confidence,
            metadata={"denied_count": denied_count, "sensitive_count": sensitive_count, "burst_count": burst_count},
        )
