"""
AgentSentinel Phase 0.6: Authoritative Attack Registry.
Centralizes attack scenario definitions, categorization, filtering, and indexing.
"""

from typing import Dict, List, Optional
from app.core.logger import logger
from app.attack.models import AttackCategory, AttackScenario, AttackSeverity
from app.attack.scenario import get_standard_scenarios


class AttackRegistry:
    """
    Authoritative registry of all standardized and custom attack scenarios.
    Provides catalog discovery, category filtering, and lifecycle management.
    """

    def __init__(self):
        self._scenarios: Dict[str, AttackScenario] = {}
        self._seed_default_scenarios()

    def _seed_default_scenarios(self):
        """Seeds the standard AgentSentinel attack scenarios."""
        standard_list = get_standard_scenarios()
        for sc in standard_list:
            self.register_scenario(sc)
        logger.info(f"AttackRegistry: Seeded {len(self._scenarios)} standard attack scenarios.")

    def register_scenario(self, scenario: AttackScenario) -> AttackScenario:
        """Registers a scenario into the active registry."""
        self._scenarios[scenario.scenario_id] = scenario
        return scenario

    def get_scenario(self, scenario_id: str) -> Optional[AttackScenario]:
        """Retrieves a scenario by its unique identifier."""
        return self._scenarios.get(scenario_id)

    def list_scenarios(
        self,
        category: Optional[AttackCategory] = None,
        severity: Optional[AttackSeverity] = None,
        enabled_only: bool = False,
    ) -> List[AttackScenario]:
        """Lists scenarios with optional filtering by category, severity, or active state."""
        results = []
        for sc in self._scenarios.values():
            if enabled_only and not sc.enabled:
                continue
            if category and sc.category != category:
                continue
            if severity and sc.severity != severity:
                continue
            results.append(sc)
        return results

    def enable_scenario(self, scenario_id: str) -> bool:
        """Enables a scenario for benchmark execution."""
        sc = self.get_scenario(scenario_id)
        if sc:
            sc.enabled = True
            return True
        return False

    def disable_scenario(self, scenario_id: str) -> bool:
        """Disables a scenario."""
        sc = self.get_scenario(scenario_id)
        if sc:
            sc.enabled = False
            return True
        return False

    def count(self) -> int:
        """Returns total count of registered scenarios."""
        return len(self._scenarios)


default_attack_registry = AttackRegistry()
