"""
AgentSentinel Phase 0.7: CLI Latency & Performance Dispersion Tool.
Evaluates execution latency distributions, standard deviations, and percentiles (p95, p99)
across System A (Unprotected) and System D (Full AgentSentinel).
Calculates precise security overhead and validates performance scalability.
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
from app.db.session import SessionLocal


def main():
    parser = argparse.ArgumentParser(
        description="AgentSentinel Phase 0.7: Latency & Performance Experiment Runner"
    )
    parser.add_argument("--repetitions", type=int, default=3, help="Number of repetitions to compute distributions")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--dataset", default="dataset-v1.0", help="Dataset ID or path")
    parser.add_argument("--output-dir", default="research/performance", help="Directory for exported results")
    args = parser.parse_args()

    print("=" * 75)
    print("AGENTSENTINEL PHASE 0.7 — LATENCY & PERFORMANCE DISPERSION EXPERIMENT")
    print("=" * 75)
    print(f"Repetitions : {args.repetitions}")
    print(f"Random Seed : {args.seed}")
    print("-" * 75)

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

    config = ExperimentConfiguration(
        experiment_name="latency_dispersion_study",
        dataset_id=dataset.dataset_id,
        dataset_version=dataset.version,
        variants=[
            SystemVariant.SYSTEM_A_UNPROTECTED,
            SystemVariant.SYSTEM_B_STATIC_POLICY,
            SystemVariant.SYSTEM_C_POLICY_AND_BEHAVIOR,
            SystemVariant.SYSTEM_D_FULL_AGENTSENTINEL,
        ],
        repetitions=args.repetitions,
        seed=args.seed,
    )

    db = None
    try:
        db = SessionLocal()
    except Exception:
        pass

    runner = ExperimentRunner(dataset=dataset)
    _, runs, _ = runner.run_experiment(config=config, db=db)

    print("\n" + "=" * 75)
    print("LATENCY DISTRIBUTION & OPERATIONAL OVERHEAD ANALYSIS")
    print("=" * 75)
    print(f"{'System Variant':<28} | {'Mean (ms)':<10} | {'Median':<8} | {'p95 (ms)':<9} | {'p99 (ms)':<9} | {'Std Dev':<8} | {'Overhead'}")
    print("-" * 75)
    for r in runs:
        m = r.metrics
        v_name = r.variant.value.replace("SYSTEM_", "")
        print(
            f"{v_name:<28} | {m.latency_mean_ms:<10.2f} | {m.latency_median_ms:<8.2f} | "
            f"{m.latency_p95_ms:<9.2f} | {m.latency_p99_ms:<9.2f} | +/-{m.latency_std_ms:<6.2f} | {m.security_overhead_ms:.2f} ms"
        )
    print("-" * 75)
    print("=" * 75)

    if db:
        db.close()


if __name__ == "__main__":
    main()
