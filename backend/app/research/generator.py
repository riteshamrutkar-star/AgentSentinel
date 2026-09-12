"""
AgentSentinel Phase 0.7: Research Dataset Generator.
Synthesizes the canonical publication-ready benchmark dataset (dataset-v1.0)
incorporating the 25 standard scenarios, structured prompt injections, and
controlled parametric variants across graduated complexity levels.
Applies leak-proof group-aware splitting (Train 60% / Val 20% / Test 20%).
"""

import copy
import uuid
from typing import Any, Dict, List, Optional

from app.attack.models import (
    AttackCategory,
    AttackSeverity,
    ThreatObjective,
)
from app.attack.scenario import get_standard_scenarios
from app.attack.taxonomy import get_threat_mapping
from app.attack.generators.prompt_injection import PromptInjectionSimulator
from app.research.models import (
    ExperimentScenario,
    DatasetSplit,
    AttackComplexity,
    utc_now,
)
from app.research.dataset import ResearchDataset


class ResearchDatasetGenerator:
    """
    Constructs the canonical publication-ready ResearchDataset (dataset-v1.0).
    Guarantees that all scenario variations maintain base_scenario_id links
    for leak-free group partitioning.
    """

    def __init__(self, dataset_id: str = "dataset-v1.0", version: str = "1.0.0"):
        self.dataset_id = dataset_id
        self.version = version

    def generate_dataset(
        self,
        include_mutations: bool = True,
        train_ratio: float = 0.60,
        val_ratio: float = 0.20,
        test_ratio: float = 0.20,
        seed: int = 42,
    ) -> ResearchDataset:
        """
        Generate complete research dataset with standard scenarios, prompt injection
        scenarios, and parametric variants, partitioned into group-aware splits.
        """
        scenarios: List[ExperimentScenario] = []

        # 1. Ingest 25 Canonical Scenarios from Phase 0.6
        standard_scenarios = get_standard_scenarios()
        for s in standard_scenarios:
            mitre_id, _, owasp_id, _ = get_threat_mapping(s.category)

            # Determine complexity
            if len(s.actions) > 1:
                complexity = AttackComplexity.MULTI_STEP
            elif s.severity == AttackSeverity.CRITICAL:
                complexity = AttackComplexity.HIGH
            elif s.severity == AttackSeverity.HIGH:
                complexity = AttackComplexity.MEDIUM
            else:
                complexity = AttackComplexity.LOW

            actions_dicts = []
            for act in s.actions:
                actions_dicts.append({
                    "step_index": act.step_index,
                    "description": act.description,
                    "tool_name": act.tool_name,
                    "arguments": act.arguments,
                    "target_resource": act.target_resource,
                    "agent_id": act.agent_id,
                    "agent_role": act.agent_role,
                    "expected_step_decision": act.expected_step_decision,
                    "delay_ms": act.delay_ms,
                })

            exp_sc = ExperimentScenario(
                scenario_id=s.scenario_id,
                scenario_version=self.version,
                base_scenario_id=s.scenario_id,  # Anchor for group splitting
                name=s.name,
                category=s.category,
                severity=s.severity,
                complexity=complexity,
                threat_objective=s.threat_objective.value if hasattr(s.threat_objective, "value") else str(s.threat_objective),
                is_adversarial=s.is_adversarial,
                is_multi_step=(len(s.actions) > 1),
                actions=actions_dicts,
                expected_decision=s.expected_security_result,
                expected_primary_detector="POLICY_ENGINE" if s.category == AttackCategory.CREDENTIAL_ACCESS else "UNIFIED_RISK_ENGINE",
                mitre_atlas_id=mitre_id,
                owasp_llm_id=owasp_id,
                split=DatasetSplit.ALL,
                metadata={"canonical": True, "required_capabilities": s.required_capabilities},
            )
            scenarios.append(exp_sc)

        # 2. Add Synthetic Prompt Injection Scenarios
        payloads = PromptInjectionSimulator.get_synthetic_payloads()
        for idx, p in enumerate(payloads, start=1):
            scen_id = f"ATK_INJ_{idx:02d}"
            base_id = scen_id
            cat = AttackCategory.PROMPT_INJECTION
            mitre_id, _, owasp_id, _ = get_threat_mapping(cat)

            actions = [{
                "step_index": 1,
                "description": f"Prompt Injection targeting {p.targeted_control}",
                "tool_name": p.simulated_tool_name,
                "arguments": {**p.simulated_arguments, "prompt_injection": p.raw_prompt_text},
                "target_resource": p.target_resource,
                "agent_id": "eval_worker",
                "agent_role": "research_worker",
                "expected_step_decision": p.expected_decision,
            }]

            scenarios.append(
                ExperimentScenario(
                    scenario_id=scen_id,
                    scenario_version=self.version,
                    base_scenario_id=base_id,
                    name=f"Structured Injection: {p.payload_category}",
                    category=cat,
                    severity=AttackSeverity.CRITICAL if p.is_adversarial else AttackSeverity.LOW,
                    complexity=AttackComplexity.MEDIUM,
                    threat_objective=ThreatObjective.INJECT_PROMPT_SYSTEM_OVERRIDE.value if p.is_adversarial else ThreatObjective.BENIGN_ROUTINE_TASK.value,
                    is_adversarial=p.is_adversarial,
                    is_multi_step=False,
                    actions=actions,
                    expected_decision=p.expected_decision,
                    expected_primary_detector="POLICY_ENGINE",
                    mitre_atlas_id=mitre_id,
                    owasp_llm_id=owasp_id,
                    split=DatasetSplit.ALL,
                    metadata={"injection_category": p.payload_category, "targeted_control": p.targeted_control},
                )
            )

        # 3. Parametric Mutations (Variants tied to base_scenario_id)
        if include_mutations:
            mutation_scenarios = self._generate_parametric_mutations(scenarios)
            scenarios.extend(mutation_scenarios)

        # Create dataset and apply group-aware partitioning
        dataset = ResearchDataset(
            dataset_id=self.dataset_id,
            version=self.version,
            description="AgentSentinel Comprehensive Empirical Research Benchmark Dataset v1.0",
            scenarios=scenarios,
        )

        dataset.apply_group_split(
            train_ratio=train_ratio,
            val_ratio=val_ratio,
            test_ratio=test_ratio,
            seed=seed,
        )
        dataset.compute_sha256()

        return dataset

    def _generate_parametric_mutations(
        self, base_scenarios: List[ExperimentScenario]
    ) -> List[ExperimentScenario]:
        """
        Generate bounded parametric mutations of base scenarios (timing variations,
        role variations, resource path encoding variations) anchored to base_scenario_id.
        """
        mutations: List[ExperimentScenario] = []

        # Target adversarial scenarios for mutations
        for sc in base_scenarios:
            if not sc.is_adversarial:
                continue

            # Variant 1: Burst timing mutation
            v1 = copy.deepcopy(sc)
            v1.scenario_id = f"{sc.scenario_id}_VAR_BURST"
            v1.base_scenario_id = sc.base_scenario_id  # Critical for group split
            v1.name = f"{sc.name} (Burst Timing Mutation)"
            for act in v1.actions:
                act["delay_ms"] = 10  # 10ms burst
            v1.metadata["mutation_type"] = "timing_burst"
            mutations.append(v1)

            # Variant 2: Role evasion mutation (attempt under low-privilege role)
            v2 = copy.deepcopy(sc)
            v2.scenario_id = f"{sc.scenario_id}_VAR_ROLE"
            v2.base_scenario_id = sc.base_scenario_id
            v2.name = f"{sc.name} (Role Impersonation Mutation)"
            for act in v2.actions:
                act["agent_role"] = "guest_observer"
            v2.metadata["mutation_type"] = "role_variation"
            mutations.append(v2)

        return mutations
