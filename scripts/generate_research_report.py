"""
AgentSentinel Phase 0.7: CLI Research Report Generator.
Synthesizes completed experiment runs and produces comprehensive, publication-grade
scientific reports in Markdown and JSON formats answering RQ1 through RQ7.
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
from app.research.reports import ResearchReportGenerator
from app.research.export import ResearchExporter
from app.db.session import SessionLocal


def main():
    parser = argparse.ArgumentParser(
        description="AgentSentinel Phase 0.7: Publication Report Generator"
    )
    parser.add_argument("--dataset", default="dataset-v1.0", help="Dataset ID or path to JSONL")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    parser.add_argument("--output-dir", default="research/reports", help="Directory for exported reports")
    args = parser.parse_args()

    print("=" * 75)
    print("AGENTSENTINEL PHASE 0.7 — PUBLICATION RESEARCH REPORT GENERATOR")
    print("=" * 75)

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
        experiment_name="publication_empirical_study",
        dataset_id=dataset.dataset_id,
        dataset_version=dataset.version,
        variants=[
            SystemVariant.SYSTEM_A_UNPROTECTED,
            SystemVariant.SYSTEM_B_STATIC_POLICY,
            SystemVariant.SYSTEM_C_POLICY_AND_BEHAVIOR,
            SystemVariant.SYSTEM_D_FULL_AGENTSENTINEL,
        ],
        repetitions=1,
        seed=args.seed,
    )

    db = None
    try:
        db = SessionLocal()
    except Exception:
        pass

    runner = ExperimentRunner(dataset=dataset)
    experiment, runs, comparisons = runner.run_experiment(config=config, db=db)
    full_run = next((r for r in runs if r.variant == SystemVariant.SYSTEM_D_FULL_AGENTSENTINEL), None)

    ablations = []
    if full_run:
        print("[*] Running formal ablation suite for report...")
        ablations = AblationStudyEngine.run_ablation_study(
            scenarios=dataset.scenarios,
            full_system_run=full_run,
            experiment_id=experiment.experiment_id,
            seed=args.seed,
            db=db,
        )

    print("[*] Generating 12-section scientific report...")
    report_md = ResearchReportGenerator.generate_markdown_report(
        experiment=experiment,
        runs=runs,
        comparisons=comparisons,
        ablations=ablations,
    )
    report_json = ResearchReportGenerator.generate_json_report(
        experiment=experiment,
        runs=runs,
        comparisons=comparisons,
        ablations=ablations,
    )

    artifacts = ResearchExporter.export_report(
        report_md=report_md,
        report_json=report_json,
        experiment_id=experiment.experiment_id,
        run_id=runs[0].run_id if runs else "exp",
        target_dir=args.output_dir,
    )

    print("\n[SUCCESS] Research report generated and exported:")
    for art in artifacts:
        print(f"  - {art.file_path} ({art.size_bytes} bytes)")
    print("=" * 75)

    if db:
        db.close()


if __name__ == "__main__":
    main()
