"""
Centralized Configuration for AgentSentinel Behavioral Anomaly Detection & Risk Intelligence.
Centralizes all detector weights, thresholds, burst windows, sequence definitions, and role capabilities.
"""

from typing import Dict, List, Set

class BehavioralConfig:
    """Centralized thresholds and weights for the behavioral risk intelligence engine."""

    # --- Severity Classification Thresholds (Normalized 0.0 - 1.0) ---
    LOW_THRESHOLD: float = 0.30        # < 0.30: Normal routine operation
    MEDIUM_THRESHOLD: float = 0.65     # 0.30 - 0.65: Elevated context / minor mismatch
    HIGH_THRESHOLD: float = 0.85       # 0.65 - 0.85: Suspicious sequence / burst / repeated failure (Escalate to REQUIRE_APPROVAL)
    # >= 0.85: Critical Threat / Multi-step attack (Escalate to BLOCK)

    # --- Detector Contribution Weights in Unified Risk Engine ---
    # Sum of weights = 1.00
    WEIGHT_STATISTICAL: float = 0.15
    WEIGHT_SEQUENCE: float = 0.30
    WEIGHT_BURST_FREQUENCY: float = 0.15
    WEIGHT_TOOL_TRANSITION: float = 0.20
    WEIGHT_ROLE_MISMATCH: float = 0.20

    # --- Burst & Frequency Detector Parameters ---
    BURST_WINDOW_SECONDS: float = 2.0          # Call interval threshold for rapid burst counting
    BURST_COUNT_THRESHOLD: int = 3             # Number of sub-window calls to trigger burst escalation
    HIGH_FREQUENCY_WINDOW_SECONDS: float = 60.0  # Window for rate calculation
    HIGH_FREQUENCY_CALL_THRESHOLD: int = 10     # Calls within 60s considered high-frequency spike
    REPEAT_TOOL_THRESHOLD: int = 4             # Consecutive calls to the exact same tool in burst window

    # --- History & Baseline Parameters ---
    MAX_HISTORY_EVENTS: int = 50               # Maximum events retrieved from PostgreSQL per session
    BASELINE_MIN_EVENTS: int = 3               # Minimum event count to establish baseline statistics

    # --- Sensitive Keywords for Resource & Tool Inspection ---
    SENSITIVE_RESOURCE_KEYWORDS: List[str] = [
        ".ssh", "id_rsa", "shadow", "passwd", ".env", "credentials",
        "private_key", "secret", "drop_table", "delete_all", "system32",
        "sam", "security", "token", "api_key"
    ]

    # --- Tool Transition Risk Weights (Pairwise Transition Matrix) ---
    # Defines risk multipliers (0.0 to 1.0) for directed transitions: (source_tool, target_tool)
    TRANSITION_RISK_MAP: Dict[tuple, float] = {
        # High-risk reconnaissance to exfiltration transitions
        ("google_search", "read_system_file"): 0.70,
        ("read_workspace_file", "read_system_file"): 0.75,
        ("read_system_file", "write_workspace_file"): 0.90,
        ("read_system_file", "google_search"): 0.80,
        ("read_system_file", "network_request"): 0.95,
        # Reconnaissance to destructive database action
        ("google_search", "drop_database_table"): 0.65,
        ("read_workspace_file", "drop_database_table"): 0.70,
        # Standard routine transitions (low risk)
        ("google_search", "google_search"): 0.05,
        ("google_search", "read_workspace_file"): 0.05,
        ("read_workspace_file", "read_workspace_file"): 0.05,
        ("read_workspace_file", "write_workspace_file"): 0.15,
    }

    # Default risk score for transitions not explicitly mapped
    DEFAULT_TRANSITION_RISK_CROSS_DOMAIN: float = 0.35
    DEFAULT_TRANSITION_RISK_SAME_DOMAIN: float = 0.05

    # --- Role to Allowed Action Types / Capability Scopes ---
    ROLE_CAPABILITY_SCOPES: Dict[str, Set[str]] = {
        "research_assistant": {"NETWORK", "READ"},
        "code_assistant": {"READ", "WRITE", "NETWORK"},
        "database_admin": {"DATABASE", "READ", "WRITE"},
        "system_admin": {"READ", "WRITE", "EXECUTE", "NETWORK", "DATABASE"},
        "default_agent": {"READ", "NETWORK"},
    }

    # Prohibited tool names per role (strict behavioral mismatch)
    ROLE_PROHIBITED_TOOLS: Dict[str, List[str]] = {
        "research_assistant": ["drop_database_table", "write_workspace_file", "execute_command"],
        "code_assistant": ["drop_database_table"],
        "default_agent": ["drop_database_table", "read_system_file", "write_workspace_file"],
    }

# Global singleton configuration
behavioral_config = BehavioralConfig()
