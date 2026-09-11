"""
Unified Risk Intelligence Engine for AgentSentinel Phase 0.3.
Orchestrates multiple specialized behavioral detectors, integrates session baselines,
calculates weighted explainable risk scores, and identifies primary risk factors.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.anomaly.base import BehavioralDetector, DetectorResult
from app.anomaly.baselines import SessionBaseline, default_baseline_engine
from app.anomaly.config import behavioral_config
from app.anomaly.detectors import (
    BurstFrequencyDetector,
    RoleCapabilityMismatchDetector,
    SequenceAnomalyDetector,
    StatisticalBaselineDetector,
    ToolTransitionDetector,
)
from app.anomaly.feature_engine import BehavioralFeatureEngine
from app.anomaly.thresholds import AnomalyLevel, classify_anomaly_level, get_recommended_action
from app.core.logger import logger
from app.events.model import SecurityEvent

class UnifiedRiskScore(BaseModel):
    """Complete multi-signal risk intelligence assessment output."""
    overall_score: float = Field(..., ge=0.0, le=1.0, description="Normalized composite risk score (0.0 to 1.0)")
    severity: AnomalyLevel = Field(..., description="Severity classification (LOW, MEDIUM, HIGH, CRITICAL)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Composite intelligence confidence score")
    primary_detector: str = Field(..., description="Detector with highest risk contribution")
    detector_contributions: Dict[str, float] = Field(default_factory=dict, description="Normalized score contribution per detector")
    detector_results: Dict[str, DetectorResult] = Field(default_factory=dict, description="Detailed individual detector outputs")
    top_risk_factors: List[str] = Field(default_factory=list, description="Top identified threat indicators")
    explanation: str = Field(..., description="Human- and machine-readable risk explanation")
    evidence: List[str] = Field(default_factory=list, description="Consolidated factual evidence entries")
    recommended_action: str = Field("ALLOW", description="Recommended action: ALLOW, LOG_AND_MONITOR, REQUIRE_APPROVAL, BLOCK")
    baseline_deviation: Optional[Dict[str, float]] = Field(None, description="Quantitative session baseline deviation metrics")

class UnifiedRiskEngine:
    """
    Orchestration core combining signals from statistical, sequence, burst,
    transition, and role mismatch detectors into a unified risk intelligence score.
    """

    def __init__(self, custom_detectors: Optional[List[BehavioralDetector]] = None):
        self.feature_engine = BehavioralFeatureEngine()
        self.baseline_engine = default_baseline_engine

        # Register default suite of 5 behavioral detectors
        self.detectors: List[BehavioralDetector] = custom_detectors or [
            StatisticalBaselineDetector(),
            SequenceAnomalyDetector(),
            BurstFrequencyDetector(),
            ToolTransitionDetector(),
            RoleCapabilityMismatchDetector(),
        ]

    def evaluate_risk(
        self,
        event: SecurityEvent,
        history: Optional[List[Any]] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> UnifiedRiskScore:
        """
        Executes all registered detectors and compiles unified explainable risk score.
        Guaranteed to fail closed and never raise uncaught exceptions.
        """
        try:
            history_list = history or []
            session_id = event.identity.session_id
            agent_id = event.identity.agent_id
            role = event.identity.role

            # 1. Extract unified behavioral features
            features = self.feature_engine.extract_features(history_list, event)

            # 2. Evaluate session baseline & calculate deviation
            baseline = self.baseline_engine.build_baseline(session_id, agent_id, role, history_list)
            deviation = self.baseline_engine.calculate_deviation(event, baseline)

            detector_context = {
                "features": features,
                "baseline": baseline,
                "deviation": deviation,
                **(context or {}),
            }

            # 3. Execute all detectors
            detector_results: Dict[str, DetectorResult] = {}
            contributions: Dict[str, float] = {}
            all_evidence: List[str] = []
            risk_factors: List[str] = []

            weighted_sum = 0.0
            max_detector_score = 0.0
            primary_detector = self.detectors[0].name
            highest_contribution = -1.0
            total_confidence_weight = 0.0

            for detector in self.detectors:
                try:
                    res = detector.detect(event, history_list, detector_context)
                except Exception as det_err:
                    logger.error(f"Detector '{detector.name}' failed: {det_err}", exc_info=True)
                    # Safe fallback for failing detector
                    res = DetectorResult.create(
                        detector_name=detector.name,
                        score=0.10,
                        explanation=f"Detector encountered internal error: {str(det_err)}",
                        confidence=0.20,
                    )

                detector_results[detector.name] = res
                contribution = detector.weight * res.score
                contributions[detector.name] = round(contribution, 3)
                weighted_sum += contribution
                total_confidence_weight += (detector.weight * res.confidence)

                if res.score > max_detector_score:
                    max_detector_score = res.score

                if contribution > highest_contribution:
                    highest_contribution = contribution
                    primary_detector = detector.name

                if res.evidence:
                    all_evidence.extend(res.evidence)

                if res.triggered:
                    risk_factors.append(f"{detector.name}: {res.explanation}")

            # Baseline deviation penalty contribution (if established)
            if deviation.get("composite_deviation", 0.0) > 0.50:
                weighted_sum += 0.10
                risk_factors.append("Session Baseline: Substantial operational deviation from established profile")

            # Incorporate peak severity: if any single detector detects CRITICAL (>= 0.85),
            # ensure unified score does not dilute critical threat below escalation threshold!
            if max_detector_score >= behavioral_config.HIGH_THRESHOLD:
                final_raw_score = max(weighted_sum, max_detector_score * 0.90)
            else:
                final_raw_score = weighted_sum

            # Strictly clamp overall score between 0.0 and 1.0
            overall_score = round(min(1.0, max(0.0, final_raw_score)), 3)
            severity = classify_anomaly_level(overall_score)
            rec_action = get_recommended_action(severity)
            confidence = round(min(1.0, max(0.20, total_confidence_weight)), 2)

            # Generate consolidated explanation
            if risk_factors:
                explanation = f"Risk Score: {overall_score:.2f} [{severity}]. Primary factor: {primary_detector}. {'; '.join(risk_factors[:3])}"
            else:
                explanation = f"Risk Score: {overall_score:.2f} [{severity}]. All behavioral signals align with benign baseline parameters."

            return UnifiedRiskScore(
                overall_score=overall_score,
                severity=severity,
                confidence=confidence,
                primary_detector=primary_detector,
                detector_contributions=contributions,
                detector_results=detector_results,
                top_risk_factors=risk_factors,
                explanation=explanation,
                evidence=all_evidence,
                recommended_action=rec_action,
                baseline_deviation=deviation,
            )
        except Exception as exc:
            logger.error(f"UnifiedRiskEngine failed: {exc}", exc_info=True)
            # Fail closed: assign critical risk
            return UnifiedRiskScore(
                overall_score=0.90,
                severity=AnomalyLevel.CRITICAL,
                confidence=0.50,
                primary_detector="FailClosedGuard",
                detector_contributions={},
                detector_results={},
                top_risk_factors=["Unified risk engine encounter error; failed closed for security."],
                explanation="Risk analysis error; failed closed to prevent unauthorized tool execution.",
                evidence=["Engine failure exception triggered safe fallback block."],
                recommended_action="BLOCK",
                baseline_deviation=None,
            )

# Global default unified risk engine instance
default_risk_engine = UnifiedRiskEngine()
default_unified_risk_engine = default_risk_engine

