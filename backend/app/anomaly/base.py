"""
Base Protocol and Domain Models for AgentSentinel Behavioral Detectors.
Defines the standard DetectorResult structure and BehavioralDetector abstract base class.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from app.anomaly.thresholds import AnomalyLevel, classify_anomaly_level
from app.events.model import SecurityEvent

class DetectorResult(BaseModel):
    """Structured output returned by an individual behavioral detector."""
    detector_name: str = Field(..., description="Unique identifier of the detector")
    score: float = Field(..., ge=0.0, le=1.0, description="Normalized risk anomaly score strictly between 0.0 and 1.0")
    severity: AnomalyLevel = Field(..., description="Severity classification (LOW, MEDIUM, HIGH, CRITICAL)")
    triggered: bool = Field(False, description="True if detector score exceeds medium anomaly threshold (>= 0.65)")
    confidence: float = Field(1.0, ge=0.0, le=1.0, description="Detection confidence based on data adequacy")
    explanation: str = Field(..., description="Human-readable explanation of findings")
    evidence: List[str] = Field(default_factory=list, description="Concrete factual evidence strings supporting the score")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary detector-specific telemetry")

    @classmethod
    def create(
        cls,
        detector_name: str,
        score: float,
        explanation: str,
        evidence: Optional[List[str]] = None,
        confidence: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "DetectorResult":
        """Factory helper guaranteeing score clamping and consistent severity classification."""
        clamped_score = round(min(1.0, max(0.0, float(score))), 3)
        severity = classify_anomaly_level(clamped_score)
        triggered = clamped_score >= 0.65

        return cls(
            detector_name=detector_name,
            score=clamped_score,
            severity=severity,
            triggered=triggered,
            confidence=round(min(1.0, max(0.0, float(confidence))), 2),
            explanation=explanation,
            evidence=evidence or [],
            metadata=metadata or {},
        )

class BehavioralDetector(ABC):
    """
    Abstract interface for all AgentSentinel behavioral detectors.
    Ensures modularity: new detectors (including future ML models) can be plugged
    into the UnifiedRiskEngine without modifying the interceptor proxy.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Returns unique detector identifier."""
        pass

    @property
    @abstractmethod
    def weight(self) -> float:
        """Returns default weighting coefficient in the unified risk engine."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Returns human-readable description of detector purpose."""
        pass

    @abstractmethod
    def detect(
        self,
        event: SecurityEvent,
        history: List[Any],
        context: Optional[Dict[str, Any]] = None
    ) -> DetectorResult:
        """
        Analyzes the current SecurityEvent against session history and returns a DetectorResult.
        Guaranteed to return normalized score within [0.0, 1.0] and never raise unhandled exceptions.
        """
        pass
