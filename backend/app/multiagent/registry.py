"""
Agent Registry for AgentSentinel Phase 0.4.
Manages persistent and in-memory agent identities, capabilities, trust tiers, and lifecycle states.
"""

from typing import Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.core.logger import logger
from app.db.crud import (
    get_agent_by_id,
    list_agents as db_list_agents,
    register_or_update_agent,
    update_agent_status,
    update_agent_trust,
)
from app.multiagent.config import multiagent_config
from app.multiagent.models import AgentCapability, AgentIdentity, AgentStatus, TrustLevel, utc_now


class AgentRegistry:
    """
    Central authoritative directory of AI Agents governing identities, capabilities, and trust.
    Maintains an in-memory cache for ultra-fast verification, backed by PostgreSQL persistence.
    """

    def __init__(self):
        self._cache: Dict[str, AgentIdentity] = {}
        self._seed_default_agents()

    def _seed_default_agents(self):
        """Seeds baseline standard agents for development, testing, and demonstration."""
        default_agents = [
            AgentIdentity(
                agent_id="agent_research_coordinator",
                name="Research Coordinator Agent",
                role="research_coordinator",
                agent_type="coordinator",
                owner="system",
                capabilities=[
                    AgentCapability.SEARCH,
                    AgentCapability.FILE_READ,
                    AgentCapability.DELEGATION,
                ],
                trust_level=TrustLevel.TRUSTED,
                trust_score=multiagent_config.DEFAULT_TRUST_SCORES[TrustLevel.TRUSTED],
                status=AgentStatus.ACTIVE,
                metadata={"scope": "research_workflow_orchestration"},
            ),
            AgentIdentity(
                agent_id="agent_research_worker",
                name="Research Worker Agent",
                role="research_worker",
                agent_type="worker",
                owner="system",
                capabilities=[
                    AgentCapability.SEARCH,
                    AgentCapability.FILE_READ,
                ],
                trust_level=TrustLevel.STANDARD,
                trust_score=multiagent_config.DEFAULT_TRUST_SCORES[TrustLevel.STANDARD],
                status=AgentStatus.ACTIVE,
                metadata={"scope": "task_execution_bounded"},
            ),
            AgentIdentity(
                agent_id="agent_db_admin",
                name="Database Administrator Agent",
                role="database_admin",
                agent_type="administrator",
                owner="system",
                capabilities=[
                    AgentCapability.DATABASE_READ,
                    AgentCapability.DATABASE_WRITE,
                    AgentCapability.FILE_READ,
                    AgentCapability.DELEGATION,
                ],
                trust_level=TrustLevel.TRUSTED,
                trust_score=multiagent_config.DEFAULT_TRUST_SCORES[TrustLevel.TRUSTED],
                status=AgentStatus.ACTIVE,
                metadata={"scope": "database_operations"},
            ),
            AgentIdentity(
                agent_id="agent_limited_guest",
                name="Limited Guest Agent",
                role="readonly_viewer",
                agent_type="guest",
                owner="system",
                capabilities=[
                    AgentCapability.SEARCH,
                ],
                trust_level=TrustLevel.LIMITED,
                trust_score=multiagent_config.DEFAULT_TRUST_SCORES[TrustLevel.LIMITED],
                status=AgentStatus.ACTIVE,
                metadata={"scope": "strictly_read_only"},
            ),
            AgentIdentity(
                agent_id="agent_untrusted_bot",
                name="Untrusted External Bot",
                role="default_agent",
                agent_type="unverified",
                owner="external",
                capabilities=[],
                trust_level=TrustLevel.UNTRUSTED,
                trust_score=multiagent_config.DEFAULT_TRUST_SCORES[TrustLevel.UNTRUSTED],
                status=AgentStatus.ACTIVE,
                metadata={"scope": "untrusted_quarantine"},
            ),
        ]

        for agent in default_agents:
            self._cache[agent.agent_id] = agent

    def register_agent(self, agent: AgentIdentity, db: Optional[Session] = None) -> AgentIdentity:
        """Registers a new agent or updates an existing identity in memory and PostgreSQL."""
        self._cache[agent.agent_id] = agent

        if db:
            try:
                register_or_update_agent(
                    db=db,
                    agent_id=agent.agent_id,
                    name=agent.name,
                    role=agent.role,
                    agent_type=agent.agent_type,
                    owner=agent.owner,
                    capabilities=[c.value for c in agent.capabilities],
                    trust_level=agent.trust_level.value,
                    trust_score=agent.trust_score,
                    status=agent.status.value,
                    metadata=agent.metadata,
                )
            except Exception as e:
                logger.warning(f"Failed to persist agent '{agent.agent_id}' to PostgreSQL: {e}")

        logger.info(f"Agent registered: ID='{agent.agent_id}', Role='{agent.role}', Trust='{agent.trust_level.value}'")
        return agent

    def get_agent(self, agent_id: str, db: Optional[Session] = None) -> Optional[AgentIdentity]:
        """Retrieves agent by identifier from cache or database."""
        if agent_id in self._cache:
            return self._cache[agent_id]

        if db:
            db_agent = get_agent_by_id(db, agent_id)
            if db_agent:
                caps = []
                for c in db_agent.capabilities_json or []:
                    try:
                        caps.append(AgentCapability(c))
                    except ValueError:
                        pass

                trust_lvl = TrustLevel.STANDARD
                try:
                    trust_lvl = TrustLevel(db_agent.trust_level)
                except ValueError:
                    pass

                agent = AgentIdentity(
                    agent_id=db_agent.agent_id,
                    name=db_agent.name,
                    role=db_agent.role,
                    agent_type=db_agent.agent_type,
                    owner=db_agent.owner,
                    capabilities=caps,
                    trust_level=trust_lvl,
                    trust_score=db_agent.trust_score,
                    status=AgentStatus(db_agent.status),
                    created_at=db_agent.created_at,
                    metadata=db_agent.metadata_json or {},
                )
                self._cache[agent_id] = agent
                return agent

        return None

    def validate_agent(self, agent_id: str, db: Optional[Session] = None) -> Tuple[bool, str]:
        """
        Validates whether an agent identity exists and is authorized to operate.
        Returns (is_valid, explanation). Fails closed if unknown, revoked, or suspended.
        """
        agent = self.get_agent(agent_id, db)
        if not agent:
            return False, f"Unknown agent '{agent_id}': Agent identity is not registered in AgentSentinel registry."

        if agent.status == AgentStatus.REVOKED:
            return False, f"Revoked agent '{agent_id}': Agent authorization has been explicitly revoked."

        if agent.status == AgentStatus.SUSPENDED:
            return False, f"Suspended agent '{agent_id}': Agent identity is currently suspended."

        return True, "Agent identity is verified and active."

    def revoke_agent(self, agent_id: str, db: Optional[Session] = None) -> bool:
        """Revokes an agent identity immediately, terminating active privileges."""
        agent = self.get_agent(agent_id, db)
        if not agent:
            return False

        agent.status = AgentStatus.REVOKED
        self._cache[agent_id] = agent

        if db:
            try:
                update_agent_status(db, agent_id, AgentStatus.REVOKED.value)
            except Exception as e:
                logger.error(f"Failed to update revocation in PostgreSQL for agent '{agent_id}': {e}")

        logger.warning(f"SECURITY EVENT: Agent '{agent_id}' has been REVOKED.")
        return True

    def list_agents(self, db: Optional[Session] = None) -> List[AgentIdentity]:
        """Returns all registered agents."""
        if db:
            db_agents = db_list_agents(db)
            if db_agents:
                for db_agent in db_agents:
                    if db_agent.agent_id not in self._cache:
                        self.get_agent(db_agent.agent_id, db)

        return list(self._cache.values())

    def update_agent_trust_score(
        self,
        agent_id: str,
        trust_score: float,
        trust_level: TrustLevel,
        db: Optional[Session] = None,
    ) -> Optional[AgentIdentity]:
        """Updates the recorded trust score and level for an agent."""
        agent = self.get_agent(agent_id, db)
        if not agent:
            return None

        agent.trust_score = round(max(0.0, min(1.0, trust_score)), 2)
        agent.trust_level = trust_level
        self._cache[agent_id] = agent

        if db:
            try:
                update_agent_trust(db, agent_id, agent.trust_score, agent.trust_level.value)
            except Exception as e:
                logger.warning(f"Failed to persist trust score update for agent '{agent_id}': {e}")

        return agent


# Global default AgentRegistry singleton
default_agent_registry = AgentRegistry()
