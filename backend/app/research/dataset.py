"""
AgentSentinel Phase 0.7: Research Dataset & Group-Aware Split Engine.
Handles loading, serializing, schema validation, SHA-256 integrity verification,
and leak-proof group-aware partitioning (Train 60% / Val 20% / Test 20%)
grouped by base scenario identifier.
"""

import csv
import hashlib
import json
import os
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.attack.models import AttackCategory, AttackSeverity
from app.research.models import (
    ExperimentScenario,
    DatasetSplit,
    AttackComplexity,
    utc_now,
)


class ResearchDataset(BaseModel):
    """
    Formal representation of a benchmark dataset for empirical security research.
    Guarantees integrity via SHA-256 and supports group-aware partitioning.
    """
    dataset_id: str = "dataset-v1.0"
    version: str = "1.0.0"
    description: str = "AgentSentinel Publication Benchmark Dataset v1.0"
    created_at: str = Field(default_factory=lambda: utc_now().isoformat())
    scenarios: List[ExperimentScenario] = Field(default_factory=list)
    sha256_hash: str = ""

    def get_scenario(self, scenario_id: str) -> Optional[ExperimentScenario]:
        """Lookup scenario by scenario_id."""
        for sc in self.scenarios:
            if sc.scenario_id == scenario_id:
                return sc
        return None

    def get_split(self, split: DatasetSplit) -> List[ExperimentScenario]:
        """Filter scenarios belonging to a specific partition split."""
        if split == DatasetSplit.ALL:
            return list(self.scenarios)
        return [sc for sc in self.scenarios if sc.split == split]

    def compute_sha256(self) -> str:
        """
        Compute deterministic SHA-256 digest over sorted canonical scenario representations.
        """
        # Sort scenarios deterministically by scenario_id
        sorted_scenarios = sorted(self.scenarios, key=lambda s: s.scenario_id)
        serialized = []
        for s in sorted_scenarios:
            d = s.model_dump() if hasattr(s, "model_dump") else s.dict()
            serialized.append(d)
        
        content_str = json.dumps(serialized, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(content_str.encode("utf-8")).hexdigest()
        self.sha256_hash = digest
        return digest

    def apply_group_split(
        self,
        train_ratio: float = 0.60,
        val_ratio: float = 0.20,
        test_ratio: float = 0.20,
        seed: int = 42,
    ) -> None:
        """
        Partition dataset into TRAIN, VALIDATION, and TEST splits.
        Uses deterministic group hashing on base_scenario_id to guarantee that all
        mutations and variants of a base scenario reside in the exact same split,
        preventing data leakage.
        """
        # Collect unique group keys (base_scenario_id or scenario_id)
        groups: Dict[str, List[ExperimentScenario]] = {}
        for sc in self.scenarios:
            group_key = sc.base_scenario_id if sc.base_scenario_id else sc.scenario_id
            if group_key not in groups:
                groups[group_key] = []
            groups[group_key].append(sc)

        # Assign each group deterministically using SHA-256 hash modulo 10000
        for group_key, scenario_list in groups.items():
            hash_input = f"{seed}:{group_key}".encode("utf-8")
            hash_val = int(hashlib.sha256(hash_input).hexdigest()[:8], 16) % 10000
            unit_val = hash_val / 10000.0

            if unit_val < train_ratio:
                assigned_split = DatasetSplit.TRAIN
            elif unit_val < (train_ratio + val_ratio):
                assigned_split = DatasetSplit.VALIDATION
            else:
                assigned_split = DatasetSplit.TEST

            for sc in scenario_list:
                sc.split = assigned_split

    def to_jsonl(self, filepath: str) -> str:
        """Export dataset to JSONL format and return file SHA-256."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        self.compute_sha256()

        with open(filepath, "w", encoding="utf-8") as f:
            for sc in self.scenarios:
                d = sc.model_dump() if hasattr(sc, "model_dump") else sc.dict()
                # Convert enums to string
                d_clean = json.loads(json.dumps(d, default=str))
                f.write(json.dumps(d_clean) + "\n")

        with open(filepath, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        return file_hash

    @classmethod
    def from_jsonl(cls, filepath: str, dataset_id: str = "dataset-v1.0") -> "ResearchDataset":
        """Load dataset from JSONL format."""
        scenarios: List[ExperimentScenario] = []
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                sc = ExperimentScenario(**d)
                scenarios.append(sc)

        ds = cls(dataset_id=dataset_id, scenarios=scenarios)
        ds.compute_sha256()
        return ds

    def to_csv(self, filepath: str) -> None:
        """Export summary table of scenarios to CSV format."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        fields = [
            "scenario_id",
            "name",
            "category",
            "severity",
            "complexity",
            "is_adversarial",
            "expected_decision",
            "expected_primary_detector",
            "mitre_atlas_id",
            "owasp_llm_id",
            "split",
        ]
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for sc in self.scenarios:
                row = {
                    "scenario_id": sc.scenario_id,
                    "name": sc.name,
                    "category": sc.category.value if hasattr(sc.category, "value") else str(sc.category),
                    "severity": sc.severity.value if hasattr(sc.severity, "value") else str(sc.severity),
                    "complexity": sc.complexity.value if hasattr(sc.complexity, "value") else str(sc.complexity),
                    "is_adversarial": sc.is_adversarial,
                    "expected_decision": sc.expected_decision,
                    "expected_primary_detector": sc.expected_primary_detector,
                    "mitre_atlas_id": sc.mitre_atlas_id,
                    "owasp_llm_id": sc.owasp_llm_id,
                    "split": sc.split.value if hasattr(sc.split, "value") else str(sc.split),
                }
                writer.writerow(row)
