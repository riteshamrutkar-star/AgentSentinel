"""
Centralized Configuration for Multi-Agent Security & Governance (Phase 0.4).
Defines maximum delegation depth, trust scores, capability mappings, and degradation rules.
"""

from typing import Dict, List
from app.multiagent.models import AgentCapability, TrustLevel


class MultiAgentConfig:
    """Configurable boundaries and thresholds for multi-agent governance."""

    # --- Delegation Depth Limit ---
    # Invariant: Chains deeper than this threshold are blocked immediately
    MAX_DELEGATION_DEPTH: int = 3

    # --- Baseline Trust Scores by Tier (0.0 to 1.0) ---
    DEFAULT_TRUST_SCORES: Dict[TrustLevel, float] = {
        TrustLevel.UNTRUSTED: 0.10,
        TrustLevel.LIMITED: 0.35,
        TrustLevel.STANDARD: 0.60,
        TrustLevel.TRUSTED: 0.85,
        TrustLevel.PRIVILEGED: 0.98,
    }

    # --- Trust Score Tier Thresholds ---
    THRESHOLD_UNTRUSTED: float = 0.20
    THRESHOLD_LIMITED: float = 0.50
    THRESHOLD_STANDARD: float = 0.75
    # >= 0.75: TRUSTED; >= 0.95: PRIVILEGED

    # --- Trust Degradation Parameters ---
    TRUST_PENALTY_PER_BLOCKED_ACTION: float = 0.15
    MAX_HISTORICAL_BLOCK_PENALTY: float = 0.45
    TRUST_PENALTY_PER_APPROVAL_REQ: float = 0.05
    MAX_APPROVAL_PENALTY: float = 0.15
    TRUST_PENALTY_PER_ESCALATION_ATTEMPT: float = 0.25

    # --- Tool to Required Capability Mapping ---
    TOOL_TO_CAPABILITY_MAP: Dict[str, AgentCapability] = {
        "google_search": AgentCapability.SEARCH,
        "read_workspace_file": AgentCapability.FILE_READ,
        "read_system_file": AgentCapability.FILE_READ,
        "write_workspace_file": AgentCapability.FILE_WRITE,
        "drop_database_table": AgentCapability.DATABASE_WRITE,
        "delegate_task": AgentCapability.DELEGATION,
    }

    # --- Role to Authorized Capabilities Mapping ---
    ROLE_DEFAULT_CAPABILITIES: Dict[str, List[AgentCapability]] = {
        "research_coordinator": [
            AgentCapability.SEARCH,
            AgentCapability.FILE_READ,
            AgentCapability.DELEGATION,
        ],
        "research_worker": [
            AgentCapability.SEARCH,
            AgentCapability.FILE_READ,
        ],
        "research_assistant": [
            AgentCapability.SEARCH,
            AgentCapability.FILE_READ,
            AgentCapability.DELEGATION,
        ],
        "code_assistant": [
            AgentCapability.FILE_READ,
            AgentCapability.FILE_WRITE,
            AgentCapability.SEARCH,
            AgentCapability.DELEGATION,
        ],
        "database_admin": [
            AgentCapability.DATABASE_READ,
            AgentCapability.DATABASE_WRITE,
            AgentCapability.FILE_READ,
            AgentCapability.DELEGATION,
        ],
        "readonly_viewer": [
            AgentCapability.SEARCH,
            AgentCapability.FILE_READ,
        ],
        "security_admin": [
            AgentCapability.SEARCH,
            AgentCapability.FILE_READ,
            AgentCapability.FILE_WRITE,
            AgentCapability.DATABASE_READ,
            AgentCapability.DATABASE_WRITE,
            AgentCapability.PROCESS_EXECUTION,
            AgentCapability.CREDENTIAL_ACCESS,
            AgentCapability.DELEGATION,
        ],
        "default_agent": [
            AgentCapability.SEARCH,
            AgentCapability.FILE_READ,
        ],
    }


multiagent_config = MultiAgentConfig()
