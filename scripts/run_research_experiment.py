"""
AgentSentinel Phase 0.7: CLI Experiment Execution Tool.
Executes rigorous comparative evaluation across configured system variants (A, B, C, D)
and generates publication-ready scientific evidence, reproducibility manifests,
statistical significance comparisons, and granular observations.
"""

import argparse
import os
import sys

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.research.models import (
    SystemVariant,
    ExperimentConfiguration,
    DatasetSplit,
)
from app.research.dataset import ResearchDataset
from app.research.generator import ResearchDatasetGenerator
from app.research.runner import ExperimentRunner
from app.research.reports import ResearchReportGenerator
from app.research.export import ResearchExporter
from app.db.session import SessionLocal


def main():
    parser = argparse.ArgumentParser(
        description="AgentSentinel Phase 0.7: Comparative Experiment Runner (Systems A, B, C, D)"
    )
    parser.add_argument("--experiment-name", default="empirical_security_benchmark", help="Name of experiment")
    parser.add_argument("--dataset", default="dataset-v1.0", help="Dataset ID or path to JSONL")
    parser.add_argument(
        "--variants",
        default="SYSTEM_A_UNPROTECTED,SYSTEM_B_STATIC_POLICY,SYSTEM_C_POLICY_AND_BEHAVIOR,SYSTEM_D_FULL_AGENTSENTINEL",
        help="Comma-separated list of SystemVariant enum names",
    )
    parser.add_argument("--repetitions", type=int, default=1, help="Number of repetitions per scenario")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    parser.add_argument("--split", default="ALL", choices=["TRAIN", "VALIDATION", "TEST", "ALL"], help="Dataset split")
    parser.add_argument("--output-dir", default="research", help="Root directory for exported artifacts")
    args = parser.parse_args()

    print("=" * 75)
    print("AGENTSENTINEL PHASE 0.7 — EMPIRICAL RESEARCH EXPERIMENT RUNNER")
    print("=" * 75)
    print(f"Experiment Name : {args.experiment_name}")
    print(f"Dataset         : {args.dataset}")
    print(f"Repetitions     : {args.repetitions}")
    print(f"Random Seed     : {args.seed}")
    print(f"Dataset Split   : {args.split}")
    print("-" * 75)

    # Load or generate dataset
    if os.path.exists(args.dataset):
        dataset = ResearchDataset.from_jsonl(args.dataset)
    else:
        dataset_path = os.path.join(args.output_dir, "datasets", f"{args.dataset}.jsonl")
        if os.path.exists(dataset_path):
            dataset = ResearchDataset.from_jsonl(dataset_path, dataset_id=args.dataset)
        else:
            print(f"[*] Generating canonical {args.dataset}...")
            gen = ResearchDatasetGenerator(dataset_id=args.dataset)
            dataset = gen.generate_dataset(include_mutations=False, seed=args.seed)

    variant_enums = []
    for v_str in args.variants.split(","):
        v_str = v_str.strip()
        try:
            variant_enums.append(SystemVariant(v_str))
        except ValueError:
            print(f"[ERROR] Unknown variant: {v_str}")
            sys.exit(1)

    config = ExperimentConfiguration(
        experiment_name=args.experiment_name,
        description="Comparative empirical baseline study across defense-in-depth layers.",
        dataset_id=dataset.dataset_id,
        dataset_version=dataset.version,
        variants=variant_enums,
        repetitions=args.repetitions,
        seed=args.seed,
        split=DatasetSplit(args.split),
    )

    db = None
    try:
        db = SessionLocal()
    except Exception:
        pass

    runner = ExperimentRunner(dataset=dataset)
    experiment, runs, comparisons = runner.run_experiment(config=config, db=db)

    print("\n" + "=" * 75)
    print("EMPIRICAL BASELINE COMPARISON RESULTS")
    print("=" * 75)
    print(f"{'System Variant':<30} | {'Prec':<6} | {'Recall':<6} | {'F1-Score':<8} | {'FPR':<6} | {'Med Lat':<8} | {'Overhead'}")
    print("-" * 75)
    for r in runs:
        m = r.metrics
        v_name = r.variant.value.replace("SYSTEM_", "")
        print(f"{v_name:<30} | {m.precision:<6.3f} | {m.detection_rate:<6.3f} | {m.f1_score:<8.3f} | {m.false_positive_rate:<6.3f} | {m.latency_median_ms:<8.2f} | {m.security_overhead_ms:.2f} ms")
    print("-" * 75)

    if comparisons:
        print("\nSTATISTICAL COMPARISONS (System D vs Baselines):")
        for cmp in comparisons:
            print(f"  {cmp.variant_b.value} vs {cmp.variant_a.value} [{cmp.metric_name}]: diff={cmp.mean_diff:+.3f}, d={cmp.cohens_d:.2f}, p={cmp.p_value}, Conclusion={cmp.conclusion}")

    # Export Reports and Artifacts
    report_md = ResearchReportGenerator.generate_markdown_report(
        experiment=experiment, runs=runs, comparisons=comparisons
    )
    report_json = ResearchReportGenerator.generate_json_report(
        experiment=experiment, runs=runs, comparisons=comparisons
    )

    report_artifacts = ResearchExporter.export_report(
        report_md=report_md,
        report_json=report_json,
        experiment_id=experiment.experiment_id,
        run_id=runs[0].run_id if runs else "exp",
        target_dir=os.path.join(args.output_dir, "reports"),
    )

    full_run = next((r for r in runs if r.variant == SystemVariant.SYSTEM_D_FULL_AGENTSENTINEL), None)
    if full_run and full_run.manifest:
        ResearchExporter.export_manifest(
            manifest=full_run.manifest,
            target_dir=os.path.join(args.output_dir, "reproducibility"),
        )

    print("\n[SUCCESS] Experiment completed and artifacts saved:")
    for art in report_artifacts:
        print(f"  - {art.file_path}")
    print("=" * 75)

    if db:
        db.close()


if __name__ == "__main__":
    main()
