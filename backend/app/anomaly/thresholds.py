from enum import Enum

class AnomalyLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

# Threshold constants for behavioral anomaly classification
LOW_THRESHOLD = 0.30       # < 0.30: Normal routine operation
MEDIUM_THRESHOLD = 0.65    # 0.30 - 0.65: Unusual context mismatch / elevated activity
HIGH_THRESHOLD = 0.85      # 0.65 - 0.85: Suspicious sequence / burst / repeated failures

def classify_anomaly_level(score: float) -> AnomalyLevel:
    """Classifies numerical score (0.0 - 1.0) into discrete AnomalyLevel."""
    if score < LOW_THRESHOLD:
        return AnomalyLevel.LOW
    elif score < MEDIUM_THRESHOLD:
        return AnomalyLevel.MEDIUM
    elif score < HIGH_THRESHOLD:
        return AnomalyLevel.HIGH
    else:
        return AnomalyLevel.CRITICAL

def get_recommended_action(level: AnomalyLevel) -> str:
    """Returns recommended security response action based on AnomalyLevel."""
    if level == AnomalyLevel.LOW:
        return "ALLOW"
    elif level == AnomalyLevel.MEDIUM:
        return "LOG_AND_MONITOR"
    elif level == AnomalyLevel.HIGH:
        return "REQUIRE_APPROVAL"
    else:
        return "BLOCK"
