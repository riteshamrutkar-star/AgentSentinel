"""
Burst and Frequency Detector for AgentSentinel.
Detects high-frequency invocation spikes, rapid tool execution bursts,
repeated tool hammering, and automated flood behaviors.
"""

from typing import Any, Dict, List, Optional
from app.anomaly.base import BehavioralDetector, DetectorResult
from app.anomaly.config import behavioral_config
from app.events.model import SecurityEvent

class BurstFrequencyDetector(BehavioralDetector):
    """
    Evaluates temporal dynamics of tool invocations:
    - Bursts of requests within sub-2-second intervals
    - Call velocity spikes exceeding standard threshold per minute
    - Consecutive rapid hammering of identical tool endpoints
    """

    @property
    def name(self) -> str:
        return "BurstFrequencyDetector"

    @property
    def weight(self) -> float:
        return behavioral_config.WEIGHT_BURST_FREQUENCY

    @property
    def description(self) -> str:
        return "Detects rapid invocation bursts, high frequency call rates, and repeated endpoint hammering."

    def detect(
        self,
        event: SecurityEvent,
        history: List[Any],
        context: Optional[Dict[str, Any]] = None
    ) -> DetectorResult:
        ctx = context or {}
        features = ctx.get("features", {})

        burst_count = int(features.get("burst_events_count", 0))
        min_interval = float(features.get("min_interval_seconds", 999.0))
        calls_last_minute = int(features.get("calls_last_minute", 1))
        repeat_tool_count = int(features.get("repeat_tool_count", 1))
        curr_tool = event.tool_action.tool_name

        score = 0.05
        evidence: List[str] = []

        # Check 1: Sub-2-second burst count
        if burst_count >= behavioral_config.BURST_COUNT_THRESHOLD:
            burst_penalty = min(0.50, burst_count * 0.12)
            score += burst_penalty
            evidence.append(f"Rapid burst detected: {burst_count} actions within {behavioral_config.BURST_WINDOW_SECONDS}s window (min gap: {min_interval:.2f}s)")

        # Check 2: High frequency per minute spike
        if calls_last_minute >= behavioral_config.HIGH_FREQUENCY_CALL_THRESHOLD:
            freq_penalty = min(0.35, (calls_last_minute - behavioral_config.HIGH_FREQUENCY_CALL_THRESHOLD + 1) * 0.08)
            score += freq_penalty
            evidence.append(f"High call velocity: {calls_last_minute} calls in last 60s exceeds threshold of {behavioral_config.HIGH_FREQUENCY_CALL_THRESHOLD}")

        # Check 3: Repeated tool pounding
        if repeat_tool_count >= behavioral_config.REPEAT_TOOL_THRESHOLD:
            repeat_penalty = min(0.35, (repeat_tool_count - 3) * 0.10)
            score += repeat_penalty
            evidence.append(f"Endpoint hammering: {repeat_tool_count} consecutive rapid calls to '{curr_tool}'")

        clamped_score = min(1.0, max(0.0, score))
        confidence = 0.85 if burst_count >= 1 or repeat_tool_count >= 2 else 0.50

        if evidence:
            explanation = f"Burst & Frequency anomaly: {'; '.join(evidence)}"
        else:
            explanation = f"Tool call interval ({min_interval:.1f}s) and invocation rate ({calls_last_minute}/min) within normal baseline parameters."

        return DetectorResult.create(
            detector_name=self.name,
            score=clamped_score,
            explanation=explanation,
            evidence=evidence,
            confidence=confidence,
            metadata={
                "burst_count": burst_count,
                "min_interval_seconds": min_interval,
                "calls_last_minute": calls_last_minute,
                "repeat_tool_count": repeat_tool_count,
            },
        )
