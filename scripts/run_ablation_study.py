"""
AgentSentinel Phase 0.7: CLI Ablation Study Runner.
Quantifies the isolated defensive necessity of each layer:
Unified Risk Engine (Behavioral), Multi-Agent Delegation Governance,
Container Sandboxing / Isolation, and Human-in-the-Loop Approvals.
Computes precise F1, Detection Rate, and Latency deltas against full defense-in-depth.
"""

import argparse
import os
import sys

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.research.models import (
    SystemVariant,
    ExperimentConfiguration,
)
from app.research.dataset import ResearchDataset
from app.research.generator import ResearchDatasetGenerator
from app.research.runner import ExperimentRunner
from app.research.ablation import AblationStudyEngine
from app.db.session import SessionLocal


def main():
    parser = argparse.ArgumentParser(
        description="AgentSentinel Phase 0.7: Layer Ablation Study Runner"
    )
    parser.add_argument("--dataset", default="dataset-v1.0", help="Dataset ID or path to JSONL")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    parser.add_argument("--output-dir", default="research/reports", help="Directory for exported reports")
    args = parser.parse_args()

    print("=" * 80)
    print("AGENTSENTINEL PHASE 0.7 — DEFENSIVE LAYER ABLATION STUDY")
    print("=" * 80)
    print(f"Dataset         : {args.dataset}")
    print(f"Random Seed     : {args.seed}")
    print("-" * 80)

    # Load or generate dataset
    if os.path.exists(args.dataset):
        dataset = ResearchDataset.from_jsonl(args.dataset)
    else:
        dataset_path = os.path.join("research", "datasets", f"{args.dataset}.jsonl")
        if os.path.exists(dataset_path):
            dataset = ResearchDataset.from_jsonl(dataset_path, dataset_id=args.dataset)
        else:
            print(f"[*] Generating dataset {args.dataset}...")
            gen = ResearchDatasetGenerator(dataset_id=args.dataset)
            dataset = gen.generate_dataset(include_mutations=False, seed=args.seed)

    db = None
    try:
        db = SessionLocal()
    except Exception:
        pass

    # 1. Run Full AgentSentinel (System D) baseline
    print("[*] Establishing Full System (System D) reference baseline...")
    cfg = ExperimentConfiguration(
        experiment_name="ablation_reference_run",
        dataset_id=dataset.dataset_id,
        dataset_version=dataset.version,
        variants=[SystemVariant.SYSTEM_D_FULL_AGENTSENTINEL],
        repetitions=1,
        seed=args.seed,
    )
    runner = ExperimentRunner(dataset=dataset)
    _, runs, _ = runner.run_experiment(config=cfg, db=db)
    full_run = runs[0]

    # 2. Run Ablation Suite
    print("[*] Evaluating 4 formal ablation variants against reference...")
    ablations = AblationStudyEngine.run_ablation_study(
        scenarios=dataset.scenarios,
        full_system_run=full_run,
        experiment_id="ablation_study_01",
        seed=args.seed,
        db=db,
    )

    print("\n" + "=" * 80)
    print("ABLATION STUDY RESULTS (Contribution of Each Defensive Layer)")
    print("=" * 80)
    print(f"{'Ablation Variant':<26} | {'Removed Layer':<32} | {'F1':<6} | {'Delta F1':<8} | {'DR':<6} | {'Delta DR':<8} | {'Med Lat'}")
    print("-" * 80)
    for ab in ablations:
        layer_short = ab.removed_layer[:32]
        print(
            f"{ab.ablation_variant.value:<26} | {layer_short:<32} | "
            f"{ab.f1_score:<6.3f} | {ab.f1_delta_vs_full:<+7.3f} | "
            f"{ab.detection_rate:<6.3f} | {ab.detection_rate_delta:<+7.3f} | {ab.latency_ms:.2f} ms"
        )
    print("-" * 80)

    print("\nDegradation Summaries:")
    for ab in ablations:
        print(f"  [{ab.ablation_variant.value}]: {ab.degradation_summary}")
    print("=" * 80)

    if db:
        db.close()


if __name__ == "__main__":
    main()
