"""
Privilege Escalation & Delegation Guard for AgentSentinel Phase 0.4.
Enforces the capability subset invariant (Delegated <= Delegator),
prevents circular delegation loops, and bounds delegation depth.
"""

from typing import List, Tuple
from app.multiagent.config import multiagent_config
from app.multiagent.models import AgentCapability, AgentIdentity


class PrivilegeEscalationDetector:
    """
    Dedicated security analyzer detecting unauthorized capability escalation,
    excessive delegation depths, and circular delegation attacks in multi-agent workflows.
    """

    @staticmethod
    def check_capability_escalation(
        delegator: AgentIdentity,
        requested_capabilities: List[AgentCapability],
    ) -> Tuple[bool, str, List[AgentCapability]]:
        """
        Enforces the fundamental security invariant:
        Delegated Capability <= Delegator Authorized Capability.

        Returns (is_escalation_detected, explanation, unauthorized_capabilities).
        """
        # 1. Delegator must possess the explicit DELEGATION capability
        if AgentCapability.DELEGATION not in delegator.capabilities:
            return (
                True,
                f"Agent '{delegator.agent_id}' lacks explicit DELEGATION capability and cannot delegate tasks.",
                requested_capabilities,
            )

        # 2. Check each requested capability against delegator's authorized capabilities
        delegator_cap_set = set(delegator.capabilities)
        unauthorized_caps = [cap for cap in requested_capabilities if cap not in delegator_cap_set]

        if unauthorized_caps:
            unauthorized_str = ", ".join([c.value for c in unauthorized_caps])
            return (
                True,
                f"Privilege escalation detected: Agent '{delegator.agent_id}' attempted to delegate capabilities "
                f"it is not authorized for [{unauthorized_str}].",
                unauthorized_caps,
            )

        return False, "Delegated capabilities are strictly within delegator authorized scope.", []

    @staticmethod
    def check_delegation_depth(current_depth: int) -> Tuple[bool, str]:
        """
        Prevents unbounded multi-agent delegation chains.
        Returns (depth_exceeded, explanation).
        """
        if current_depth > multiagent_config.MAX_DELEGATION_DEPTH:
            return (
                True,
                f"Delegation depth exceeded configured maximum: Current depth {current_depth} "
                f"exceeds limit of {multiagent_config.MAX_DELEGATION_DEPTH}.",
            )
        return False, f"Delegation depth {current_depth} within allowable limit ({multiagent_config.MAX_DELEGATION_DEPTH})."

    @staticmethod
    def check_circular_delegation(
        target_agent_id: str,
        provenance_chain: List[str],
    ) -> Tuple[bool, str]:
        """
        Detects cyclical or recursive delegation loops (e.g. Agent A -> Agent B -> Agent A).
        Returns (is_circular, explanation).
        """
        if not provenance_chain:
            return False, "Provenance chain is clean."

        if target_agent_id in provenance_chain:
            chain_str = " -> ".join(provenance_chain + [target_agent_id])
            return (
                True,
                f"Circular delegation chain detected: Target agent '{target_agent_id}' already exists "
                f"in delegation chain [{chain_str}].",
            )

        return False, "No circular delegation patterns detected."


default_escalation_detector = PrivilegeEscalationDetector()
