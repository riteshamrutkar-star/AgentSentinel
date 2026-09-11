"""
AgentSentinel Multi-Agent Security & Agent-to-Agent Governance Subsystem (Phase 0.4).
Exposes agent identities, capability definitions, trust engines, delegation managers,
interception gateways, and framework adapters.
"""

from app.multiagent.adapter import (
    AgentFrameworkAdapter,
    LangChainMultiAgentAdapter,
    default_multiagent_adapter,
)
from app.multiagent.config import MultiAgentConfig, multiagent_config
from app.multiagent.delegation import DelegationManager, default_delegation_manager
from app.multiagent.escalation import (
    PrivilegeEscalationDetector,
    default_escalation_detector,
)
from app.multiagent.interceptor import (
    AgentMessageInterceptor,
    default_message_interceptor,
)
from app.multiagent.models import (
    AgentCapability,
    AgentIdentity,
    AgentMessage,
    AgentStatus,
    AgentTrustResult,
    DelegationContext,
    DelegationDecision,
    MessageType,
    TrustLevel,
)
from app.multiagent.registry import AgentRegistry, default_agent_registry
from app.multiagent.trust import AgentTrustEngine, default_trust_engine

__all__ = [
    "TrustLevel",
    "AgentStatus",
    "AgentCapability",
    "MessageType",
    "AgentIdentity",
    "AgentTrustResult",
    "AgentMessage",
    "DelegationContext",
    "DelegationDecision",
    "MultiAgentConfig",
    "multiagent_config",
    "AgentRegistry",
    "default_agent_registry",
    "AgentTrustEngine",
    "default_trust_engine",
    "PrivilegeEscalationDetector",
    "default_escalation_detector",
    "DelegationManager",
    "default_delegation_manager",
    "AgentMessageInterceptor",
    "default_message_interceptor",
    "AgentFrameworkAdapter",
    "LangChainMultiAgentAdapter",
    "default_multiagent_adapter",
]
