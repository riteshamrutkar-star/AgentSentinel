from typing import List, Optional
from sqlalchemy.orm import Session

from app.anomaly.features import BehavioralFeatureExtractor
from app.anomaly.scorer import AnomalyAnalysisResult, StatisticalAnomalyScorer
from app.anomaly.thresholds import AnomalyLevel
from app.db.crud import list_security_events
from app.events.factory import apply_decision, enrich_event_security
from app.events.model import SecurityEvent
from app.events.schema import PolicyResult

class BehavioralAnomalyDetector:
    """
    Main Behavioral Anomaly Detection Engine for AgentSentinel.
    Retrieves historical session context from PostgreSQL, extracts feature vectors,
    computes composite anomaly scores, and applies behavioral verdict escalations.
    """

    def __init__(self):
        self.extractor = BehavioralFeatureExtractor()
        self.scorer = StatisticalAnomalyScorer()

    def analyze_session(self, db: Session, session_id: str, security_event: SecurityEvent) -> AnomalyAnalysisResult:
        """
        Analyzes recent session events from PostgreSQL and enriches current event's anomaly metrics.
        """
        # Fetch historical events for session from PostgreSQL
        historical_events = list_security_events(db, session_id=session_id, limit=50)

        # Extract behavioral features
        current_tool = security_event.tool_action.tool_name
        current_role = security_event.identity.role
        features = self.extractor.extract_features(historical_events, current_tool, current_role)

        # Score session features
        result = self.scorer.score_session_features(session_id, features)

        # Update event security context with anomaly score
        security_event.security_context.anomaly_score = result.anomaly_score

        if result.flagged:
            if result.matched_pattern and result.matched_pattern not in security_event.security_context.threat_flags:
                security_event.security_context.threat_flags.append(result.matched_pattern)
            if "BEHAVIORAL_ANOMALY_DETECTED" not in security_event.security_context.threat_flags:
                security_event.security_context.threat_flags.append("BEHAVIORAL_ANOMALY_DETECTED")

        # Behavioral Escalation: If policy verdict was ALLOW, but anomaly is HIGH/CRITICAL
        current_verdict = security_event.decision_context.policy_result
        if current_verdict == PolicyResult.ALLOW:
            if result.anomaly_level == AnomalyLevel.CRITICAL:
                apply_decision(
                    security_event,
                    policy_result=PolicyResult.DENY,
                    reason=f"BEHAVIORAL BLOCK: Critical anomaly detected ({result.reason})",
                )
                result.recommended_action = "BLOCK"
            elif result.anomaly_level == AnomalyLevel.HIGH:
                apply_decision(
                    security_event,
                    policy_result=PolicyResult.REQUIRE_APPROVAL,
                    reason=f"BEHAVIORAL ESCALATION: High anomaly score requires human approval ({result.reason})",
                    approval_required=True,
                )
                result.recommended_action = "REQUIRE_APPROVAL"

        return result

# Global default anomaly detector instance
default_anomaly_detector = BehavioralAnomalyDetector()
