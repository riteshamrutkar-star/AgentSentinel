"""
AgentSentinel Phase 0.6: Multi-Step Attack Chain Engine.
Orchestrates sequential, ordered multi-stage attack behaviors across agents,
sessions, and delegation contexts, recording the exact step at which defenses interrupt the chain.
"""

import time
import uuid
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.attack.models import (
    AttackAction,
    AttackCategory,
    AttackChain,
    AttackExecutionResult,
    AttackSeverity,
    AttackStepResult,
    BaselineSystemType,
)
from app.attack.context import AttackSimulationContext


class AttackChainEngine:
    """
    Coordinates execution of multi-step attack chains, managing session state,
    provenance propagation, and attack-chain interruption detection.
    """

    def __init__(self, attack_engine=None):
        if attack_engine is None:
            from app.attack.engine import default_attack_engine
            self.attack_engine = default_attack_engine
        else:
            self.attack_engine = attack_engine

    def set_engine(self, engine):
        self.attack_engine = engine

    def execute_chain(
        self,
        chain: Optional[Any] = None,
        baseline: BaselineSystemType = BaselineSystemType.SYSTEM_D_FULL_AGENTSENTINEL,
        context: Optional[AttackSimulationContext] = None,
        db: Optional[Session] = None,
        scenario: Optional[Any] = None,
    ):
        """
        Executes an attack chain or multi-step scenario sequentially. Halts execution if a step is blocked
        or requires approval, recording the exact interruption step, findings, and attack graph.
        """
        if not self.attack_engine:
            from app.attack.engine import default_attack_engine
            self.attack_engine = default_attack_engine

        target = scenario or chain
        if isinstance(target, AttackChain):
            from app.attack.models import AttackScenario, ThreatObjective
            target = AttackScenario(
                scenario_id=target.chain_id,
                name=target.name,
                category=target.category,
                description=target.description,
                severity=target.severity,
                threat_objective=ThreatObjective.BYPASS_POLICY_DENY,
                is_adversarial=True,
                actions=target.actions,
                is_multi_step=True,
            )

        return self.attack_engine.execute_scenario(
            scenario=target,
            baseline=baseline,
            context=context,
            db=db,
        )
