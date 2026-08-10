from typing import Any, Dict, Optional
from pydantic import BaseModel, Field
from app.anomaly.thresholds import AnomalyLevel, classify_anomaly_level, get_recommended_action

class AnomalyAnalysisResult(BaseModel):
    """Structured output returned by the Behavioral Anomaly Detection Engine."""
    session_id: str = Field(..., description="Target session UUID")
    anomaly_score: float = Field(..., description="Calculated composite anomaly score (0.0 to 1.0)")
    anomaly_level: AnomalyLevel = Field(..., description="Severity classification (LOW, MEDIUM, HIGH, CRITICAL)")
    flagged: bool = Field(False, description="True if anomaly score exceeds medium threshold")
    reason: str = Field(..., description="Human-readable explanation of detected behavior")
    matched_pattern: Optional[str] = Field(None, description="Identified threat sequence pattern if any")
    recommended_action: str = Field("ALLOW", description="Recommended action: ALLOW, LOG_AND_MONITOR, REQUIRE_APPROVAL, BLOCK")
    features: Dict[str, float] = Field(default_factory=dict, description="Extracted feature metrics dictionary")

class StatisticalAnomalyScorer:
    """
    Statistical and heuristic scoring engine for behavioral anomaly analysis.
    Computes a normalized composite score from extracted session features.
    """

    @staticmethod
    def score_session_features(session_id: str, features: Dict[str, float]) -> AnomalyAnalysisResult:
        denied_count = features.get("denied_count", 0.0)
        sensitive_count = features.get("sensitive_action_count", 0.0)
        burst_count = features.get("burst_count", 0.0)
        ratio_denied = features.get("ratio_denied", 0.0)
        transition_penalty = features.get("transition_penalty", 0.0)
        role_mismatch = features.get("role_mismatch", 0.0)
        seq_length = features.get("sequence_length", 1.0)

        # Baseline calculation
        score = 0.05  # Base normal noise

        # Denied attempts component (weight: 0.25)
        if denied_count >= 1:
            score += min(0.35, denied_count * 0.15)

        # Sensitive action frequency component (weight: 0.25)
        if sensitive_count >= 1:
            score += min(0.35, sensitive_count * 0.15)

        # Rapid burst activity component (weight: 0.15)
        if burst_count >= 2:
            score += min(0.20, burst_count * 0.08)

        # Sequence transition & role mismatch penalties
        score += transition_penalty
        score += role_mismatch

        # High denied ratio penalty
        if ratio_denied > 0.40 and seq_length > 2:
            score += 0.25

        # Normalize score between 0.0 and 1.0
        final_score = round(min(1.0, max(0.0, score)), 3)
        anomaly_level = classify_anomaly_level(final_score)
        flagged = final_score >= 0.65

        # Determine matched pattern and explanation
        matched_pattern = None
        reasons = []

        if transition_penalty >= 0.35 and sensitive_count >= 1:
            matched_pattern = "PROBE_TO_EXFILTRATE_SEQUENCE"
            reasons.append("Suspicious sequence transition: research probing followed by sensitive file access")

        if denied_count >= 2:
            reasons.append(f"Repeated denied tool invocations detected ({int(denied_count)} failures)")

        if burst_count >= 3:
            reasons.append(f"High-frequency tool execution burst detected ({int(burst_count)} rapid actions)")

        if role_mismatch > 0.0:
            reasons.append("Tool invocation deviates from assigned agent role capabilities")

        if not reasons:
            reason = "Session activity aligns with expected routine baseline behavior."
        else:
            reason = "; ".join(reasons)

        rec_action = get_recommended_action(anomaly_level)

        return AnomalyAnalysisResult(
            session_id=session_id,
            anomaly_score=final_score,
            anomaly_level=anomaly_level,
            flagged=flagged,
            reason=reason,
            matched_pattern=matched_pattern,
            recommended_action=rec_action,
            features=features,
        )
