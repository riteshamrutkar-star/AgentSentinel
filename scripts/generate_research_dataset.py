"""
AgentSentinel Phase 0.7: CLI Dataset Generation Tool.
Generates, validates, and partitions canonical research benchmark dataset (dataset-v1.0)
using leak-proof group-aware partitioning (Train 60% / Val 20% / Test 20%).
Exports JSONL and CSV formats with deterministic SHA-256 verification hash.
"""

import argparse
import os
import sys

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.research.generator import ResearchDatasetGenerator
from app.research.export import ResearchExporter
from app.research.models import DatasetSplit


def main():
    parser = argparse.ArgumentParser(
        description="AgentSentinel Phase 0.7: Research Dataset Generator (dataset-v1.0)"
    )
    parser.add_argument("--dataset-id", default="dataset-v1.0", help="Unique identifier for dataset")
    parser.add_argument("--version", default="1.0.0", help="Semantic version of dataset")
    parser.add_argument("--output-dir", default="research/datasets", help="Target output directory")
    parser.add_argument("--seed", type=int, default=42, help="Deterministic seed for group splitting")
    parser.add_argument(
        "--no-mutations",
        action="store_true",
        help="Exclude parametric mutations, generating only standard scenarios",
    )
    args = parser.parse_args()

    print("=" * 70)
    print("AGENTSENTINEL PHASE 0.7 — RESEARCH DATASET GENERATOR")
    print("=" * 70)
    print(f"Dataset ID      : {args.dataset_id}")
    print(f"Version         : {args.version}")
    print(f"Include Mut.    : {not args.no_mutations}")
    print(f"Deterministic S.: {args.seed}")
    print(f"Target Dir      : {args.output_dir}")
    print("-" * 70)

    generator = ResearchDatasetGenerator(dataset_id=args.dataset_id, version=args.version)
    dataset = generator.generate_dataset(
        include_mutations=not args.no_mutations,
        train_ratio=0.60,
        val_ratio=0.20,
        test_ratio=0.20,
        seed=args.seed,
    )

    artifacts = ResearchExporter.export_dataset(dataset=dataset, target_dir=args.output_dir)

    train_scenarios = dataset.get_split(DatasetSplit.TRAIN)
    val_scenarios = dataset.get_split(DatasetSplit.VALIDATION)
    test_scenarios = dataset.get_split(DatasetSplit.TEST)

    print(f"[SUCCESS] Dataset successfully generated and partitioned:")
    print(f"  Total Scenarios : {len(dataset.scenarios)}")
    print(f"  TRAIN Split     : {len(train_scenarios)} ({len(train_scenarios)/len(dataset.scenarios)*100:.1f}%)")
    print(f"  VALIDATION Split: {len(val_scenarios)} ({len(val_scenarios)/len(dataset.scenarios)*100:.1f}%)")
    print(f"  TEST Split      : {len(test_scenarios)} ({len(test_scenarios)/len(dataset.scenarios)*100:.1f}%)")
    print(f"  Dataset SHA-256 : {dataset.sha256_hash}")
    print("-" * 70)
    print("Exported Artifacts:")
    for art in artifacts:
        print(f"  - {art.filename} ({art.size_bytes} bytes, SHA-256: {art.sha256_hash[:16]}...)")
    print("=" * 70)


if __name__ == "__main__":
    main()
