"""
AgentSentinel Phase 0.7: Research Experiment & Dataset Registry.
In-memory and persistent catalog managing registered benchmark datasets,
experiments, multi-variant execution runs, and exported research artifacts.
"""

from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.research.models import (
    Experiment,
    ExperimentRun,
    ResearchArtifact,
)
from app.research.dataset import ResearchDataset


class ExperimentRegistry:
    """
    Central catalog storing experiments, execution runs, datasets, and artifacts.
    """

    def __init__(self):
        self._datasets: Dict[str, ResearchDataset] = {}
        self._experiments: Dict[str, Experiment] = {}
        self._runs: Dict[str, ExperimentRun] = {}
        self._artifacts: Dict[str, List[ResearchArtifact]] = {}

    def register_dataset(self, dataset: ResearchDataset) -> None:
        """Register benchmark dataset."""
        self._datasets[dataset.dataset_id] = dataset

    def get_dataset(self, dataset_id: str) -> Optional[ResearchDataset]:
        """Fetch dataset by ID."""
        return self._datasets.get(dataset_id)

    def list_datasets(self) -> List[Dict[str, Any]]:
        """List metadata for all registered datasets."""
        return [
            {
                "dataset_id": ds.dataset_id,
                "version": ds.version,
                "description": ds.description,
                "total_scenarios": len(ds.scenarios),
                "sha256_hash": ds.sha256_hash,
            }
            for ds in self._datasets.values()
        ]

    def register_experiment(self, experiment: Experiment) -> None:
        """Register an experiment."""
        self._experiments[experiment.experiment_id] = experiment

    def get_experiment(self, experiment_id: str) -> Optional[Experiment]:
        """Retrieve experiment by ID."""
        return self._experiments.get(experiment_id)

    def list_experiments(self) -> List[Experiment]:
        """List all experiments."""
        return list(self._experiments.values())

    def register_run(self, run: ExperimentRun) -> None:
        """Register an execution run."""
        self._runs[run.run_id] = run

    def get_run(self, run_id: str) -> Optional[ExperimentRun]:
        """Retrieve execution run by ID."""
        return self._runs.get(run_id)

    def list_runs_for_experiment(self, experiment_id: str) -> List[ExperimentRun]:
        """List all runs belonging to a specific experiment."""
        return [r for r in self._runs.values() if r.experiment_id == experiment_id]

    def register_artifact(self, artifact: ResearchArtifact) -> None:
        """Register an exported research artifact."""
        if artifact.run_id not in self._artifacts:
            self._artifacts[artifact.run_id] = []
        self._artifacts[artifact.run_id].append(artifact)

    def get_artifacts_for_run(self, run_id: str) -> List[ResearchArtifact]:
        """Fetch all artifacts produced by a run."""
        return self._artifacts.get(run_id, [])


default_experiment_registry = ExperimentRegistry()
