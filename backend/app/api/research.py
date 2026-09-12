"""
AgentSentinel Phase 0.7: Research REST API Router.
Exposes endpoints for dataset generation, multi-variant experiment execution,
ablation studies, reproducibility verification, raw observations, and publication reports.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.research.models import (
    SystemVariant,
    ExperimentConfiguration,
    ExperimentScenario,
    DatasetSplit,
)
from app.research.baselines import SYSTEM_CONFIGS, get_system_config
from app.research.dataset import ResearchDataset
from app.research.generator import ResearchDatasetGenerator
from app.research.runner import ExperimentRunner
from app.research.ablation import AblationStudyEngine
from app.research.reproducibility import ReproducibilityManager
from app.research.reports import ResearchReportGenerator
from app.research.export import ResearchExporter
from app.research.registry import default_experiment_registry

router = APIRouter(prefix="/api/v1/research", tags=["Research & Experimentation"])

# Initialize default dataset in registry if not present
_default_gen = ResearchDatasetGenerator()
_init_dataset = _default_gen.generate_dataset(include_mutations=False)
default_experiment_registry.register_dataset(_init_dataset)


# --- Schemas ---

class DatasetGenerateRequest(BaseModel):
    dataset_id: str = "dataset-v1.0"
    version: str = "1.0.0"
    include_mutations: bool = True
    train_ratio: float = 0.60
    val_ratio: float = 0.20
    test_ratio: float = 0.20
    seed: int = 42


class ReproducibilityVerifyRequest(BaseModel):
    run_a_id: str
    run_b_id: str
    f1_tolerance: float = 0.0001
    dr_tolerance: float = 0.0001


class AblationRunRequest(BaseModel):
    experiment_id: str
    dataset_id: str = "dataset-v1.0"
    seed: int = 42


# --- Endpoints ---

@router.get("/baselines")
def list_system_baselines() -> List[Dict[str, Any]]:
    """Lists all formal system baselines and ablation configurations."""
    return [
        {
            "variant": cfg.variant.value,
            "policy_enabled": cfg.policy_enabled,
            "behavioral_enabled": cfg.behavioral_enabled,
            "multiagent_enabled": cfg.multiagent_enabled,
            "execution_gateway_enabled": cfg.execution_gateway_enabled,
            "approval_enabled": cfg.approval_enabled,
            "sandboxing_enabled": cfg.sandboxing_enabled,
            "description": cfg.description,
        }
        for cfg in SYSTEM_CONFIGS.values()
    ]


@router.get("/datasets")
def list_datasets() -> List[Dict[str, Any]]:
    """Lists all registered benchmark research datasets."""
    return default_experiment_registry.list_datasets()


@router.get("/datasets/{dataset_id}")
def get_dataset(dataset_id: str, split: Optional[DatasetSplit] = None) -> Dict[str, Any]:
    """Retrieve metadata and scenarios for a specific dataset."""
    ds = default_experiment_registry.get_dataset(dataset_id)
    if not ds:
        raise HTTPException(status_code=404, detail=f"Dataset '{dataset_id}' not found.")

    scenarios = ds.get_split(split) if split else ds.scenarios
    return {
        "dataset_id": ds.dataset_id,
        "version": ds.version,
        "description": ds.description,
        "created_at": ds.created_at,
        "sha256_hash": ds.sha256_hash,
        "total_scenarios": len(scenarios),
        "scenarios": [s.model_dump() if hasattr(s, "model_dump") else s.dict() for s in scenarios],
    }


@router.post("/datasets/generate")
def generate_dataset(req: DatasetGenerateRequest, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Generate or regenerate canonical benchmark dataset (dataset-v1.0)."""
    generator = ResearchDatasetGenerator(dataset_id=req.dataset_id, version=req.version)
    dataset = generator.generate_dataset(
        include_mutations=req.include_mutations,
        train_ratio=req.train_ratio,
        val_ratio=req.val_ratio,
        test_ratio=req.test_ratio,
        seed=req.seed,
    )
    default_experiment_registry.register_dataset(dataset)

    # Persist dataset metadata to database
    try:
        from app.db.crud import record_research_dataset
        record_research_dataset(
            db=db,
            dataset_id=dataset.dataset_id,
            version=dataset.version,
            description=dataset.description,
            total_scenarios=len(dataset.scenarios),
            sha256_hash=dataset.sha256_hash,
        )
    except Exception:
        pass

    return {
        "dataset_id": dataset.dataset_id,
        "version": dataset.version,
        "total_scenarios": len(dataset.scenarios),
        "sha256_hash": dataset.sha256_hash,
        "message": "Dataset generated and registered successfully with group-aware partitioning.",
    }


@router.post("/experiments/run")
def run_experiment(config: ExperimentConfiguration, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Executes an empirical security experiment across configured system variants (A, B, C, D).
    Computes rigorous metrics, manifests, and statistical comparisons.
    """
    ds = default_experiment_registry.get_dataset(config.dataset_id)
    if not ds:
        # Fallback to init dataset or generate
        ds = _init_dataset

    runner = ExperimentRunner(dataset=ds)
    experiment, runs, comparisons = runner.run_experiment(config=config, db=db)

    # Register experiment and runs in memory catalog
    default_experiment_registry.register_experiment(experiment)
    for r in runs:
        default_experiment_registry.register_run(r)

    # Generate Markdown and JSON reports
    report_md = ResearchReportGenerator.generate_markdown_report(
        experiment=experiment,
        runs=runs,
        comparisons=comparisons,
    )
    report_json = ResearchReportGenerator.generate_json_report(
        experiment=experiment,
        runs=runs,
        comparisons=comparisons,
    )

    return {
        "experiment_id": experiment.experiment_id,
        "name": experiment.name,
        "status": experiment.status,
        "total_runs": len(runs),
        "runs": [r.model_dump() if hasattr(r, "model_dump") else r.dict() for r in runs],
        "statistical_comparisons": [c.model_dump() if hasattr(c, "model_dump") else c.dict() for c in comparisons],
        "report_markdown": report_md,
    }


@router.get("/experiments")
def list_experiments(db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    """List all executed research experiments."""
    exps = default_experiment_registry.list_experiments()
    return [e.model_dump() if hasattr(e, "model_dump") else e.dict() for e in exps]


@router.get("/experiments/{experiment_id}")
def get_experiment(experiment_id: str) -> Dict[str, Any]:
    """Retrieve details and runs for a specific experiment."""
    exp = default_experiment_registry.get_experiment(experiment_id)
    if not exp:
        raise HTTPException(status_code=404, detail=f"Experiment '{experiment_id}' not found.")
    runs = default_experiment_registry.list_runs_for_experiment(experiment_id)
    return {
        "experiment": exp.model_dump() if hasattr(exp, "model_dump") else exp.dict(),
        "runs": [r.model_dump() if hasattr(r, "model_dump") else r.dict() for r in runs],
    }


@router.get("/runs/{run_id}")
def get_run(run_id: str) -> Dict[str, Any]:
    """Retrieve run metrics, manifest, and error analysis records."""
    r = default_experiment_registry.get_run(run_id)
    if not r:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found.")
    return r.model_dump() if hasattr(r, "model_dump") else r.dict()


@router.get("/runs/{run_id}/observations")
def get_run_observations(
    run_id: str, limit: int = 100, db: Session = Depends(get_db)
) -> List[Dict[str, Any]]:
    """Retrieve granular ScenarioObservations for empirical inspection."""
    try:
        from app.db.crud import list_research_observations
        db_obs = list_research_observations(db, run_id=run_id, limit=limit)
        return [
            {
                "observation_id": o.observation_id,
                "scenario_id": o.scenario_id,
                "variant": o.variant,
                "expected_outcome": o.expected_outcome,
                "actual_outcome": o.actual_outcome,
                "attribution": o.attribution,
                "latency_ms": o.latency_ms,
                "passed": o.passed,
            }
            for o in db_obs
        ]
    except Exception:
        return []


@router.post("/ablations/run")
def run_ablation_study(req: AblationRunRequest, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Run ablation suite comparing Full AgentSentinel against 4 ablation variants."""
    ds = default_experiment_registry.get_dataset(req.dataset_id) or _init_dataset
    runs = default_experiment_registry.list_runs_for_experiment(req.experiment_id)
    full_run = next(
        (r for r in runs if r.variant == SystemVariant.SYSTEM_D_FULL_AGENTSENTINEL), None
    )

    if not full_run:
        raise HTTPException(
            status_code=400,
            detail=f"Experiment '{req.experiment_id}' must have a completed System D run before running ablations.",
        )

    ablation_results = AblationStudyEngine.run_ablation_study(
        scenarios=ds.scenarios,
        full_system_run=full_run,
        experiment_id=req.experiment_id,
        seed=req.seed,
        db=db,
    )

    return {
        "experiment_id": req.experiment_id,
        "ablation_results": [
            a.model_dump() if hasattr(a, "model_dump") else a.dict() for a in ablation_results
        ],
    }


@router.get("/reports/{experiment_id}")
def get_report(experiment_id: str) -> Dict[str, Any]:
    """Retrieve 12-section scientific report in Markdown and JSON formats."""
    exp = default_experiment_registry.get_experiment(experiment_id)
    if not exp:
        raise HTTPException(status_code=404, detail=f"Experiment '{experiment_id}' not found.")
    runs = default_experiment_registry.list_runs_for_experiment(experiment_id)

    md = ResearchReportGenerator.generate_markdown_report(
        experiment=exp,
        runs=runs,
        comparisons=[],
    )
    json_data = ResearchReportGenerator.generate_json_report(
        experiment=exp,
        runs=runs,
        comparisons=[],
    )

    return {
        "experiment_id": experiment_id,
        "report_markdown": md,
        "report_json": json_data,
    }


@router.post("/reproducibility/verify")
def verify_reproducibility(req: ReproducibilityVerifyRequest) -> Dict[str, Any]:
    """Verify bitwise or statistical reproducibility between two execution runs."""
    run_a = default_experiment_registry.get_run(req.run_a_id)
    run_b = default_experiment_registry.get_run(req.run_b_id)

    if not run_a or not run_b:
        raise HTTPException(status_code=404, detail="One or both runs not found.")

    report = ReproducibilityManager.verify_reproducibility(
        run_a=run_a,
        run_b=run_b,
        f1_tolerance=req.f1_tolerance,
        dr_tolerance=req.dr_tolerance,
    )
    return report
