"""
AgentSentinel Phase 0.7: Research Artifact Exporter & Sanitizer.
Handles export of datasets, reports, reproducibility manifests, and granular observations
into standardized file formats (JSON, JSONL, CSV, Markdown).
Ensures zero credential or secret leakage through automated sanitization.
"""

import csv
import hashlib
import json
import os
import re
from typing import Any, Dict, List, Optional

from app.research.models import (
    ResearchArtifact,
    ScenarioObservation,
    ReproducibilityManifest,
    utc_now,
)
from app.research.dataset import ResearchDataset

# Regex patterns for sensitive credential redacting
SENSITIVE_PATTERNS = [
    re.compile(r"(api[ _-]?key|secret|token|password|auth|authorization)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{8,})", re.IGNORECASE),
    re.compile(r"(ssh-rsa|PRIVATE KEY|BEGIN RSA PRIVATE KEY)[^\n]+", re.IGNORECASE),
]


class ResearchExporter:
    """
    Exports sanitized experimental artifacts and computes verification hashes.
    """

    @classmethod
    def sanitize_text(cls, text: str) -> str:
        """Redact potential secrets or authentication tokens."""
        sanitized = text
        for pattern in SENSITIVE_PATTERNS:
            sanitized = pattern.sub(r"\1: [REDACTED_SECRET]", sanitized)
        return sanitized

    @classmethod
    def sanitize_dict(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively redact dictionary fields that may contain sensitive data."""
        clean: Dict[str, Any] = {}
        for k, v in data.items():
            if any(term in k.lower() for term in ("password", "secret", "token", "auth_key", "api_key")):
                clean[k] = "[REDACTED_SECRET]"
            elif isinstance(v, dict):
                clean[k] = cls.sanitize_dict(v)
            elif isinstance(v, list):
                clean[k] = [cls.sanitize_dict(item) if isinstance(item, dict) else item for item in v]
            elif isinstance(v, str):
                clean[k] = cls.sanitize_text(v)
            else:
                clean[k] = v
        return clean

    @classmethod
    def export_dataset(
        cls, dataset: ResearchDataset, target_dir: str = "research/datasets"
    ) -> List[ResearchArtifact]:
        """Export dataset to JSONL and CSV."""
        os.makedirs(target_dir, exist_ok=True)
        artifacts: List[ResearchArtifact] = []

        jsonl_filename = f"{dataset.dataset_id}.jsonl"
        jsonl_path = os.path.join(target_dir, jsonl_filename)
        jsonl_hash = dataset.to_jsonl(jsonl_path)
        size_jsonl = os.path.getsize(jsonl_path)

        artifacts.append(
            ResearchArtifact(
                run_id="dataset",
                experiment_id="dataset",
                artifact_type="DATASET",
                filename=jsonl_filename,
                file_path=jsonl_path,
                file_format="JSONL",
                sha256_hash=jsonl_hash,
                size_bytes=size_jsonl,
            )
        )

        csv_filename = f"{dataset.dataset_id}.csv"
        csv_path = os.path.join(target_dir, csv_filename)
        dataset.to_csv(csv_path)
        with open(csv_path, "rb") as f:
            csv_hash = hashlib.sha256(f.read()).hexdigest()
        size_csv = os.path.getsize(csv_path)

        artifacts.append(
            ResearchArtifact(
                run_id="dataset",
                experiment_id="dataset",
                artifact_type="DATASET",
                filename=csv_filename,
                file_path=csv_path,
                file_format="CSV",
                sha256_hash=csv_hash,
                size_bytes=size_csv,
            )
        )

        return artifacts

    @classmethod
    def export_report(
        cls,
        report_md: str,
        report_json: Dict[str, Any],
        experiment_id: str,
        run_id: str,
        target_dir: str = "research/reports",
    ) -> List[ResearchArtifact]:
        """Export report in Markdown and sanitized JSON."""
        os.makedirs(target_dir, exist_ok=True)
        artifacts: List[ResearchArtifact] = []

        # Markdown
        md_filename = f"report_{experiment_id}.md"
        md_path = os.path.join(target_dir, md_filename)
        sanitized_md = cls.sanitize_text(report_md)
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(sanitized_md)
        with open(md_path, "rb") as f:
            md_hash = hashlib.sha256(f.read()).hexdigest()

        artifacts.append(
            ResearchArtifact(
                run_id=run_id,
                experiment_id=experiment_id,
                artifact_type="REPORT_MD",
                filename=md_filename,
                file_path=md_path,
                file_format="MD",
                sha256_hash=md_hash,
                size_bytes=os.path.getsize(md_path),
            )
        )

        # JSON
        json_filename = f"report_{experiment_id}.json"
        json_path = os.path.join(target_dir, json_filename)
        sanitized_json = cls.sanitize_dict(report_json)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(sanitized_json, f, indent=2, default=str)
        with open(json_path, "rb") as f:
            json_hash = hashlib.sha256(f.read()).hexdigest()

        artifacts.append(
            ResearchArtifact(
                run_id=run_id,
                experiment_id=experiment_id,
                artifact_type="REPORT_JSON",
                filename=json_filename,
                file_path=json_path,
                file_format="JSON",
                sha256_hash=json_hash,
                size_bytes=os.path.getsize(json_path),
            )
        )

        return artifacts

    @classmethod
    def export_observations(
        cls,
        observations: List[ScenarioObservation],
        experiment_id: str,
        run_id: str,
        target_dir: str = "research/observations",
    ) -> List[ResearchArtifact]:
        """Export granular ScenarioObservation list to CSV and JSONL."""
        os.makedirs(target_dir, exist_ok=True)
        artifacts: List[ResearchArtifact] = []

        # CSV
        csv_filename = f"observations_{run_id}.csv"
        csv_path = os.path.join(target_dir, csv_filename)
        fields = [
            "observation_id",
            "scenario_id",
            "trial_index",
            "system_variant",
            "category",
            "severity",
            "complexity",
            "expected_outcome",
            "actual_outcome",
            "final_decision",
            "attribution",
            "latency_ms",
            "passed",
        ]

        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for obs in observations:
                writer.writerow({
                    "observation_id": obs.observation_id,
                    "scenario_id": obs.scenario_id,
                    "trial_index": obs.trial_index,
                    "system_variant": obs.system_variant.value if hasattr(obs.system_variant, "value") else str(obs.system_variant),
                    "category": obs.category,
                    "severity": obs.severity,
                    "complexity": obs.complexity,
                    "expected_outcome": obs.expected_outcome,
                    "actual_outcome": obs.actual_outcome,
                    "final_decision": obs.final_decision,
                    "attribution": obs.attribution.value if hasattr(obs.attribution, "value") else str(obs.attribution),
                    "latency_ms": obs.latency_ms,
                    "passed": obs.passed,
                })

        with open(csv_path, "rb") as f:
            csv_hash = hashlib.sha256(f.read()).hexdigest()

        artifacts.append(
            ResearchArtifact(
                run_id=run_id,
                experiment_id=experiment_id,
                artifact_type="OBSERVATIONS_CSV",
                filename=csv_filename,
                file_path=csv_path,
                file_format="CSV",
                sha256_hash=csv_hash,
                size_bytes=os.path.getsize(csv_path),
            )
        )

        return artifacts

    @classmethod
    def export_manifest(
        cls,
        manifest: ReproducibilityManifest,
        target_dir: str = "research/reproducibility",
    ) -> ResearchArtifact:
        """Export reproducibility manifest to JSON."""
        os.makedirs(target_dir, exist_ok=True)
        filename = f"manifest_{manifest.run_id}.json"
        path = os.path.join(target_dir, filename)

        d = manifest.model_dump() if hasattr(manifest, "model_dump") else manifest.dict()
        sanitized = cls.sanitize_dict(d)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(sanitized, f, indent=2, default=str)

        with open(path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        return ResearchArtifact(
            run_id=manifest.run_id,
            experiment_id=manifest.experiment_id,
            artifact_type="MANIFEST",
            filename=filename,
            file_path=path,
            file_format="JSON",
            sha256_hash=file_hash,
            size_bytes=os.path.getsize(path),
        )
