"""
Agent Trust Engine for AgentSentinel Phase 0.4.
Calculates deterministic, explainable agent trust scores, evaluates behavioral degradation,
and maintains trust level tiers based on verifiable interaction history.
"""

from typing import List, Optional
from sqlalchemy.orm import Session

from app.core.logger import logger
from app.db.crud import list_security_events
from app.multiagent.config import multiagent_config
from app.multiagent.models import AgentIdentity, AgentStatus, AgentTrustResult, TrustLevel
from app.multiagent.registry import AgentRegistry, default_agent_registry


class AgentTrustEngine:
    """
    Evaluates real-time, explainable trust for AI agents.
    Combines configured baseline trust, historical policy compliance, approval friction,
    and privilege escalation attempts into a normalized score (0.0 to 1.0).
    """

    def __init__(self, registry: Optional[AgentRegistry] = None):
        self.registry = registry or default_agent_registry

    def evaluate_agent_trust(
        self,
        agent_id: str,
        db: Optional[Session] = None,
        context_penalties: Optional[List[str]] = None,
    ) -> AgentTrustResult:
        """
        Evaluates current trust for an agent based on baseline configuration and historical telemetry.
        Fails closed with UNTRUSTED (score 0.0) if agent is unknown or revoked.
        """
        agent = self.registry.get_agent(agent_id, db)
        if not agent:
            return AgentTrustResult(
                agent_id=agent_id,
                trust_score=0.0,
                trust_level=TrustLevel.UNTRUSTED,
                factors=["Agent identity not found in registry"],
                explanation=f"Unknown agent '{agent_id}' is evaluated as UNTRUSTED (Score: 0.00).",
                confidence=1.0,
            )

        if agent.status == AgentStatus.REVOKED:
            return AgentTrustResult(
                agent_id=agent_id,
                trust_score=0.0,
                trust_level=TrustLevel.UNTRUSTED,
                factors=["Agent identity has been explicitly revoked"],
                explanation=f"Revoked agent '{agent_id}' has zero trust (Score: 0.00).",
                confidence=1.0,
            )

        # 1. Base trust score from configured tier
        base_score = multiagent_config.DEFAULT_TRUST_SCORES.get(agent.trust_level, 0.60)
        current_score = base_score
        factors: List[str] = [f"Base tier: {agent.trust_level.value} ({base_score:.2f})"]

        # 2. Historical violation inspection from PostgreSQL audit logs (if db available)
        blocked_count = 0
        approval_count = 0

        if db:
            try:
                # Query recent events associated with this agent
                events = list_security_events(db, limit=50)
                agent_events = [e for e in events if getattr(e, "agent_id", None) == agent_id]

                for evt in agent_events:
                    dec = str(getattr(evt, "decision_result", "")).upper()
                    if dec in ("BLOCK", "DENY"):
                        blocked_count += 1
                    elif dec in ("REQUIRE_APPROVAL", "PENDING"):
                        approval_count += 1

                if blocked_count > 0:
                    block_penalty = min(
                        multiagent_config.MAX_HISTORICAL_BLOCK_PENALTY,
                        blocked_count * multiagent_config.TRUST_PENALTY_PER_BLOCKED_ACTION
                    )
                    current_score -= block_penalty
                    factors.append(f"Recent policy violations: {blocked_count} blocked actions (-{block_penalty:.2f})")

                if approval_count > 0:
                    approval_penalty = min(
                        multiagent_config.MAX_APPROVAL_PENALTY,
                        approval_count * multiagent_config.TRUST_PENALTY_PER_APPROVAL_REQ
                    )
                    current_score -= approval_penalty
                    factors.append(f"Sensitive operations requiring approval: {approval_count} (-{approval_penalty:.2f})")

            except Exception as e:
                logger.warning(f"Error checking historical telemetry for agent '{agent_id}': {e}")

        # 3. Contextual penalties (e.g. privilege escalation attempt in current interaction)
        if context_penalties:
            for p in context_penalties:
                if "escalation" in p.lower():
                    current_score -= multiagent_config.TRUST_PENALTY_PER_ESCALATION_ATTEMPT
                    factors.append(f"Privilege escalation attempt detected (-{multiagent_config.TRUST_PENALTY_PER_ESCALATION_ATTEMPT:.2f})")
                elif "depth" in p.lower():
                    current_score -= 0.20
                    factors.append("Delegation depth violation (-0.20)")
                elif "circular" in p.lower():
                    current_score -= 0.30
                    factors.append("Circular delegation pattern detected (-0.30)")

        # 4. Normalize and clamp score within [0.0, 1.0]
        clamped_score = round(max(0.0, min(1.0, current_score)), 2)

        # 5. Determine resulting trust level tier based on thresholds
        if clamped_score < multiagent_config.THRESHOLD_UNTRUSTED:
            evaluated_level = TrustLevel.UNTRUSTED
        elif clamped_score < multiagent_config.THRESHOLD_LIMITED:
            evaluated_level = TrustLevel.LIMITED
        elif clamped_score < multiagent_config.THRESHOLD_STANDARD:
            evaluated_level = TrustLevel.STANDARD
        elif clamped_score < 0.95:
            evaluated_level = TrustLevel.TRUSTED
        else:
            evaluated_level = TrustLevel.PRIVILEGED

        # Construct clear explanation
        if clamped_score < base_score:
            explanation = (
                f"Trust degraded from baseline {agent.trust_level.value} to {evaluated_level.value} "
                f"(Score: {clamped_score:.2f}) due to: {'; '.join(factors[1:])}."
            )
        else:
            explanation = f"Agent '{agent_id}' maintains verified {evaluated_level.value} trust tier (Score: {clamped_score:.2f})."

        # Update registry if trust score changed significantly
        if abs(clamped_score - agent.trust_score) >= 0.05:
            self.registry.update_agent_trust_score(agent_id, clamped_score, evaluated_level, db)

        return AgentTrustResult(
            agent_id=agent_id,
            trust_score=clamped_score,
            trust_level=evaluated_level,
            factors=factors,
            explanation=explanation,
            confidence=0.90 if db else 0.75,
        )


# Global default AgentTrustEngine singleton
default_trust_engine = AgentTrustEngine()
