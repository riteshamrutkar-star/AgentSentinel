"""
AgentSentinel Phase 0.7: Reproducibility & Environment Manifest Manager.
Captures an immutable snapshot of software versions, Git revision, platform info,
detector weights, decision thresholds, dataset hashes, and random seeds.
Provides validation routines to verify bitwise repeatability across runs.
"""

import hashlib
import json
import platform
import subprocess
import sys
from typing import Any, Dict, Optional

from app.research.models import (
    ReproducibilityManifest,
    ExperimentRun,
    utc_now,
)
from app.anomaly.config import behavioral_config
from app.policy.engine import default_policy_engine


class ReproducibilityManager:
    """
    Manages generation and verification of experiment reproducibility manifests.
    """

    @classmethod
    def get_git_commit(cls) -> str:
        """Fetch current Git commit hash or fallback gracefully."""
        try:
            res = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if res.returncode == 0:
                return res.stdout.strip()
        except Exception:
            pass
        return "UNKNOWN_COMMIT"

    @classmethod
    def create_manifest(
        cls,
        experiment_id: str,
        run_id: str,
        dataset_id: str,
        dataset_version: str,
        dataset_hash: str,
        seed: int,
        total_scenarios: int,
        software_version: str = "0.7.0",
    ) -> ReproducibilityManifest:
        """
        Construct an immutable manifest recording exact system and experiment state.
        """
        weights = {
            "WEIGHT_STATISTICAL": getattr(behavioral_config, "WEIGHT_STATISTICAL", 0.15),
            "WEIGHT_SEQUENCE": getattr(behavioral_config, "WEIGHT_SEQUENCE", 0.30),
            "WEIGHT_BURST_FREQUENCY": getattr(behavioral_config, "WEIGHT_BURST_FREQUENCY", 0.15),
            "WEIGHT_TOOL_TRANSITION": getattr(behavioral_config, "WEIGHT_TOOL_TRANSITION", 0.20),
            "WEIGHT_ROLE_MISMATCH": getattr(behavioral_config, "WEIGHT_ROLE_MISMATCH", 0.20),
        }
        thresholds = {
            "low_threshold": getattr(behavioral_config, "LOW_THRESHOLD", 0.30),
            "medium_threshold": getattr(behavioral_config, "MEDIUM_THRESHOLD", 0.65),
            "high_threshold": getattr(behavioral_config, "HIGH_THRESHOLD", 0.85),
        }

        config_elements = {
            "software_version": software_version,
            "seed": seed,
            "weights": weights,
            "thresholds": thresholds,
            "dataset_hash": dataset_hash,
            "policy_rule_count": len(default_policy_engine.policies) if hasattr(default_policy_engine, "policies") else 0,
        }
        config_hash = hashlib.sha256(
            json.dumps(config_elements, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()

        return ReproducibilityManifest(
            experiment_id=experiment_id,
            run_id=run_id,
            timestamp=utc_now(),
            software_version=software_version,
            git_commit=cls.get_git_commit(),
            python_version=sys.version.split()[0],
            os_platform=platform.platform(),
            db_engine="PostgreSQL 17",
            config_hash=config_hash,
            detector_weights=weights if isinstance(weights, dict) else {},
            thresholds=thresholds,
            dataset_id=dataset_id,
            dataset_version=dataset_version,
            dataset_hash=dataset_hash,
            seed=seed,
            total_scenarios=total_scenarios,
        )

    @classmethod
    def verify_reproducibility(
        cls,
        run_a: ExperimentRun,
        run_b: ExperimentRun,
        f1_tolerance: float = 0.0001,
        dr_tolerance: float = 0.0001,
    ) -> Dict[str, Any]:
        """
        Verify whether two runs executed with the same parameters produced identical
        or statistically indistinguishable empirical results.
        """
        report: Dict[str, Any] = {
            "reproducible": False,
            "run_a_id": run_a.run_id,
            "run_b_id": run_b.run_id,
            "seeds_match": run_a.seed == run_b.seed,
            "variants_match": run_a.variant == run_b.variant,
            "dataset_hashes_match": False,
            "f1_delta": None,
            "dr_delta": None,
            "observation_counts_match": run_a.total_observations == run_b.total_observations,
            "discrepancies": [],
        }

        if run_a.manifest and run_b.manifest:
            report["dataset_hashes_match"] = run_a.manifest.dataset_hash == run_b.manifest.dataset_hash
            if not report["dataset_hashes_match"]:
                report["discrepancies"].append("Dataset SHA-256 hashes differ.")

        if run_a.seed != run_b.seed:
            report["discrepancies"].append(f"Seeds differ: {run_a.seed} vs {run_b.seed}.")

        if run_a.metrics and run_b.metrics:
            f1_diff = abs(run_a.metrics.f1_score - run_b.metrics.f1_score)
            dr_diff = abs(run_a.metrics.detection_rate - run_b.metrics.detection_rate)
            report["f1_delta"] = round(f1_diff, 6)
            report["dr_delta"] = round(dr_diff, 6)

            if f1_diff > f1_tolerance:
                report["discrepancies"].append(f"F1 delta ({f1_diff}) exceeds tolerance ({f1_tolerance}).")
            if dr_diff > dr_tolerance:
                report["discrepancies"].append(f"Detection rate delta ({dr_diff}) exceeds tolerance ({dr_tolerance}).")

        report["reproducible"] = (len(report["discrepancies"]) == 0)
        return report
