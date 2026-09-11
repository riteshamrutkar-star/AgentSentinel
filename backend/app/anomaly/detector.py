"""
Behavioral Anomaly Detection Subsystem for AgentSentinel Phase 0.3.
Wraps the UnifiedRiskEngine to provide backward-compatible session analysis,
risk intelligence enrichment, and deterministic fail-closed policy escalation.
"""

from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.anomaly.engine import UnifiedRiskEngine, UnifiedRiskScore, default_risk_engine
from app.anomaly.features import BehavioralFeatureExtractor
from app.anomaly.scorer import AnomalyAnalysisResult, StatisticalAnomalyScorer
from app.anomaly.thresholds import AnomalyLevel
from app.db.crud import list_security_events
from app.events.factory import apply_decision, enrich_event_security
from app.events.model import SecurityEvent
from app.events.schema import PolicyResult

class BehavioralAnomalyDetector:
    """
    Main Behavioral Security Control Engine for AgentSentinel.
    Retrieves historical session events from PostgreSQL, executes the multi-detector
    UnifiedRiskEngine, enriches event metadata, and applies strict precedence escalations.
    """

    def __init__(self, risk_engine: Optional[UnifiedRiskEngine] = None):
        self.risk_engine = risk_engine or default_risk_engine
        # Retain backward-compatible references for older test fixtures
        self.extractor = BehavioralFeatureExtractor()
        self.scorer = StatisticalAnomalyScorer()

    def analyze_session(
        self,
        db: Session,
        session_id: str,
        security_event: SecurityEvent
    ) -> AnomalyAnalysisResult:
        """
        Analyzes session history from PostgreSQL and enriches event with unified risk intelligence.
        Returns a backward-compatible AnomalyAnalysisResult while durably logging multi-detector telemetry.
        """
        # 1. Retrieve historical events for session from PostgreSQL
        historical_events = list_security_events(db, session_id=session_id, limit=50)

        # 2. Evaluate multi-signal risk through UnifiedRiskEngine
        unified_risk: UnifiedRiskScore = self.risk_engine.evaluate_risk(
            event=security_event,
            history=historical_events
        )

        # 3. Update event security context with unified score
        security_event.security_context.anomaly_score = unified_risk.overall_score

        # Attach rich risk intelligence into audit metadata
        if not security_event.audit_context.metadata:
            security_event.audit_context.metadata = {}
        security_event.audit_context.metadata["unified_risk"] = {
            "overall_score": unified_risk.overall_score,
            "severity": unified_risk.severity.value,
            "confidence": unified_risk.confidence,
            "primary_detector": unified_risk.primary_detector,
            "contributions": unified_risk.detector_contributions,
            "top_risk_factors": unified_risk.top_risk_factors,
            "evidence": unified_risk.evidence,
        }

        # 4. Populate threat flags
        if unified_risk.overall_score >= 0.65:
            if "BEHAVIORAL_ANOMALY_DETECTED" not in security_event.security_context.threat_flags:
                security_event.security_context.threat_flags.append("BEHAVIORAL_ANOMALY_DETECTED")

            # Attach sequence pattern flag if identified
            seq_res = unified_risk.detector_results.get("SequenceAnomalyDetector")
            if seq_res and seq_res.metadata.get("matched_pattern"):
                pat = seq_res.metadata["matched_pattern"]
                if pat not in security_event.security_context.threat_flags:
                    security_event.security_context.threat_flags.append(pat)

        # 5. Enforce Policy + Behavioral Precedence Rules
        # Rule: Policy BLOCK is NEVER weakened.
        # Rule: Policy REQUIRE_APPROVAL is NEVER weakened to ALLOW.
        # Rule: Policy ALLOW escalates to BLOCK (Critical) or REQUIRE_APPROVAL (High).
        current_verdict = security_event.decision_context.policy_result

        if current_verdict == PolicyResult.ALLOW:
            if unified_risk.severity == AnomalyLevel.CRITICAL:
                apply_decision(
                    security_event,
                    policy_result=PolicyResult.DENY,
                    reason=f"BEHAVIORAL BLOCK: Critical risk detected by {unified_risk.primary_detector} ({unified_risk.explanation})",
                )
                unified_risk.recommended_action = "BLOCK"
            elif unified_risk.severity == AnomalyLevel.HIGH:
                apply_decision(
                    security_event,
                    policy_result=PolicyResult.REQUIRE_APPROVAL,
                    reason=f"BEHAVIORAL ESCALATION: High risk detected by {unified_risk.primary_detector} requires human approval",
                    approval_required=True,
                )
                unified_risk.recommended_action = "REQUIRE_APPROVAL"

        elif current_verdict == PolicyResult.REQUIRE_APPROVAL:
            if unified_risk.severity == AnomalyLevel.CRITICAL:
                apply_decision(
                    security_event,
                    policy_result=PolicyResult.DENY,
                    reason=f"BEHAVIORAL BLOCK: Critical risk escalation on approval-pending action ({unified_risk.primary_detector})",
                )
                unified_risk.recommended_action = "BLOCK"

        # Determine matched pattern for legacy response compatibility
        matched_pattern = None
        seq_res = unified_risk.detector_results.get("SequenceAnomalyDetector")
        if seq_res and seq_res.metadata.get("matched_pattern"):
            matched_pattern = seq_res.metadata["matched_pattern"]

        # 6. Return backward-compatible AnomalyAnalysisResult
        return AnomalyAnalysisResult(
            session_id=session_id,
            anomaly_score=unified_risk.overall_score,
            anomaly_level=unified_risk.severity,
            flagged=unified_risk.overall_score >= 0.65,
            reason=unified_risk.explanation,
            matched_pattern=matched_pattern,
            recommended_action=unified_risk.recommended_action,
            features=unified_risk.detector_contributions,
        )

# Global default anomaly detector instance
default_anomaly_detector = BehavioralAnomalyDetector()
