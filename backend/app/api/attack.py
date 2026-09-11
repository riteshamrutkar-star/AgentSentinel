"""
AgentSentinel Phase 0.6: Attack Simulation, Threat Intelligence & Security Validation REST APIs.
Provides endpoints for catalog discovery, scenario execution across comparative baselines,
deterministic replays, threat intelligence findings, benchmark evaluations, and control effectiveness matrices.
"""

from typing import Any, Dict, List, Optional
import time
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.logger import logger
from app.db.session import get_db
from app.db.crud import (
    get_attack_run_by_id,
    list_attack_runs,
    get_security_finding_by_id,
    list_security_findings,
    record_attack_scenario,
    list_attack_scenarios,
    get_attack_scenario_by_id,
)
from app.attack.models import (
    AttackCategory,
    AttackSeverity,
    ThreatObjective,
    BaselineSystemType,
    AttackScenario,
    AttackExecutionResult,
    SecurityFinding,
    AttackGraph,
    ControlEffectivenessRow,
    BenchmarkRunSummary,
)
from app.attack.registry import default_attack_registry
from app.attack.engine import default_attack_engine
from app.attack.taxonomy import get_threat_mapping, get_taxonomy_entry, TAXONOMY_CATALOG

router = APIRouter(prefix="/api/v1", tags=["Attack Simulation & Threat Intelligence"])

# In-memory store for benchmark run history
_benchmark_runs: Dict[str, BenchmarkRunSummary] = {}


# --- Request / Response Models ---

class AttackRunRequest(BaseModel):
    scenario_id: str = Field(..., description="Target AttackScenario ID to execute")
    baseline_type: BaselineSystemType = Field(
        default=BaselineSystemType.SYSTEM_D_FULL_AGENTSENTINEL,
        description="Comparative baseline architecture (SYSTEM_A_UNPROTECTED, SYSTEM_B_STATIC_POLICY, SYSTEM_C_POLICY_AND_BEHAVIOR, SYSTEM_D_FULL_AGENTSENTINEL)",
    )
    persist_to_db: bool = Field(default=True, description="Whether to persist execution audit record to PostgreSQL")


class AttackReplayRequest(BaseModel):
    scenario_id: Optional[str] = Field(None, description="Scenario ID to replay")
    run_id: Optional[str] = Field(None, description="Previous run ID to replay from")
    baseline_type: BaselineSystemType = Field(
        default=BaselineSystemType.SYSTEM_D_FULL_AGENTSENTINEL,
        description="Baseline architecture for replay execution",
    )


class BenchmarkRunRequest(BaseModel):
    baselines: Optional[List[BaselineSystemType]] = Field(
        default=None,
        description="List of baseline architectures to benchmark against (defaults to all 4)",
    )
    category: Optional[AttackCategory] = Field(
        default=None,
        description="Optional category filter (benchmarks all 25 scenarios if omitted)",
    )
    persist_to_db: bool = Field(default=True, description="Whether to persist audit records")


class AttackScenarioResponse(BaseModel):
    scenario_id: str
    name: str
    category: str
    severity: str
    objective: str
    description: str
    mitre_atlas_id: str
    owasp_llm_id: str
    expected_security_result: str
    expected_primary_detector: str
    is_multi_step: bool
    step_count: int
    enabled: bool


class ScenarioRunResponse(BaseModel):
    execution_result: AttackExecutionResult
    findings: List[SecurityFinding]
    graph: AttackGraph


# --- Endpoints ---

@router.get("/attacks", response_model=List[AttackScenarioResponse])
def list_scenarios(
    category: Optional[str] = Query(None, description="Filter by attack category"),
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    enabled: Optional[bool] = Query(None, description="Filter by enabled state"),
    db: Session = Depends(get_db),
):
    """
    Returns the comprehensive catalog of 25 standardized attack scenarios.
    Filters by category, severity, or active state.
    """
    cat_filter = None
    if category:
        try:
            cat_filter = AttackCategory(category.upper())
        except ValueError:
            pass

    scenarios = default_attack_registry.list_scenarios(
        category=cat_filter,
        enabled_only=(enabled is True),
    )

    if severity:
        sev_val = severity.upper()
        scenarios = [s for s in scenarios if s.severity.value == sev_val]

    response = []
    for sc in scenarios:
        mapping = get_taxonomy_entry(sc.category)
        mitre_id = sc.mitre_atlas_id or (mapping.mitre_atlas_id if mapping else "UNMAPPED")
        owasp_id = sc.owasp_llm_id or (mapping.owasp_llm_id if mapping else "UNMAPPED")
        response.append(
            AttackScenarioResponse(
                scenario_id=sc.scenario_id,
                name=sc.name,
                category=sc.category.value,
                severity=sc.severity.value,
                objective=sc.objective,
                description=sc.description,
                mitre_atlas_id=mitre_id,
                owasp_llm_id=owasp_id,
                expected_security_result=sc.expected_security_result,
                expected_primary_detector=sc.expected_primary_detector,
                is_multi_step=sc.is_multi_step,
                step_count=len(sc.actions),
                enabled=sc.enabled,
            )
        )
    return response


@router.get("/attacks/{scenario_id}", response_model=AttackScenario)
def get_scenario_detail(scenario_id: str):
    """
    Retrieves full details and step definitions for a specific attack scenario.
    """
    scenario = default_attack_registry.get_scenario(scenario_id)
    if not scenario:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack scenario '{scenario_id}' not found in registry.",
        )
    return scenario


@router.post("/attacks/run", response_model=ScenarioRunResponse)
def run_attack_simulation(
    request: AttackRunRequest,
    db: Session = Depends(get_db),
):
    """
    Executes an attack scenario against a chosen comparative baseline.
    Zero-bypass: all actions traverse the authentic security pipeline.
    Returns complete step outcomes, threat findings, and attack graph.
    """
    scenario = default_attack_registry.get_scenario(request.scenario_id)
    if not scenario:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack scenario '{request.scenario_id}' not found.",
        )

    db_session = db if request.persist_to_db else None
    exec_res, findings, graph = default_attack_engine.execute_scenario(
        scenario=scenario,
        baseline=request.baseline_type,
        db=db_session,
    )

    return ScenarioRunResponse(
        execution_result=exec_res,
        findings=findings,
        graph=graph,
    )


@router.post("/attacks/replay", response_model=ScenarioRunResponse)
def replay_attack_simulation(
    request: AttackReplayRequest,
    db: Session = Depends(get_db),
):
    """
    Replays an attack simulation deterministically.
    Can replay by scenario_id or re-run a previous run_id under an alternative baseline.
    """
    scenario_id = request.scenario_id
    if not scenario_id and request.run_id:
        prev_run = get_attack_run_by_id(db, request.run_id)
        if prev_run:
            scenario_id = prev_run.scenario_id
        elif request.run_id in default_attack_engine._execution_history:
            scenario_id = default_attack_engine._execution_history[request.run_id].scenario_id

    if not scenario_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Must provide either scenario_id or a valid prior run_id to replay.",
        )

    scenario = default_attack_registry.get_scenario(scenario_id)
    if not scenario:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scenario '{scenario_id}' not found for replay.",
        )

    exec_res, findings, graph = default_attack_engine.execute_scenario(
        scenario=scenario,
        baseline=request.baseline_type,
        db=db,
    )

    return ScenarioRunResponse(
        execution_result=exec_res,
        findings=findings,
        graph=graph,
    )


@router.get("/attacks/{run_id}/findings", response_model=List[SecurityFinding])
def get_run_findings(
    run_id: str,
    db: Session = Depends(get_db),
):
    """
    Retrieves threat intelligence findings discovered during a specific attack run.
    """
    findings = default_attack_engine.get_findings_for_run(run_id)
    if not findings:
        db_findings = list_security_findings(db, run_id=run_id)
        if db_findings:
            findings = [
                SecurityFinding(
                    finding_id=f.finding_id,
                    run_id=f.run_id,
                    scenario_id=f.scenario_id,
                    category=AttackCategory(f.category) if f.category in [c.value for c in AttackCategory] else AttackCategory.TOOL_ABUSE,
                    severity=AttackSeverity(f.severity) if f.severity in [s.value for s in AttackSeverity] else AttackSeverity.HIGH,
                    title=f.title,
                    description=f.description or "",
                    evidence=f.evidence_json or [],
                    prevented_by=f.prevented_by or "POLICY_ENGINE",
                    mitre_atlas_id=f.mitre_atlas_id or "UNMAPPED",
                    owasp_llm_category=f.owasp_llm_id or "UNMAPPED",
                    remediation=f.remediation or "",
                )
                for f in db_findings
            ]
    return findings


@router.get("/threats", response_model=List[SecurityFinding])
def list_threat_findings(
    category: Optional[str] = Query(None, description="Filter by attack category"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    scenario_id: Optional[str] = Query(None, description="Filter by scenario ID"),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    """
    Returns security findings across all attack runs with threat intelligence attributes.
    """
    db_findings = list_security_findings(
        db,
        scenario_id=scenario_id,
        category=category,
        severity=severity,
        limit=limit,
    )
    findings: List[SecurityFinding] = []
    for f in db_findings:
        findings.append(
            SecurityFinding(
                finding_id=f.finding_id,
                run_id=f.run_id,
                scenario_id=f.scenario_id,
                category=AttackCategory(f.category) if f.category in [c.value for c in AttackCategory] else AttackCategory.TOOL_ABUSE,
                severity=AttackSeverity(f.severity) if f.severity in [s.value for s in AttackSeverity] else AttackSeverity.HIGH,
                title=f.title,
                description=f.description or "",
                evidence=f.evidence_json or [],
                prevented_by=f.prevented_by or "POLICY_ENGINE",
                mitre_atlas_id=f.mitre_atlas_id or "UNMAPPED",
                owasp_llm_category=f.owasp_llm_id or "UNMAPPED",
                remediation=f.remediation or "",
            )
        )
    return findings


@router.get("/threats/{finding_id}", response_model=SecurityFinding)
def get_threat_finding_detail(
    finding_id: str,
    db: Session = Depends(get_db),
):
    """
    Retrieves detailed threat finding with MITRE ATLAS, OWASP LLM, and remediation guidance.
    """
    f = get_security_finding_by_id(db, finding_id)
    if not f:
        # Search engine memory
        for fnd_list in default_attack_engine._findings_history.values():
            for item in fnd_list:
                if item.finding_id == finding_id:
                    return item
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security finding '{finding_id}' not found.",
        )

    return SecurityFinding(
        finding_id=f.finding_id,
        run_id=f.run_id,
        scenario_id=f.scenario_id,
        category=AttackCategory(f.category) if f.category in [c.value for c in AttackCategory] else AttackCategory.TOOL_ABUSE,
        severity=AttackSeverity(f.severity) if f.severity in [s.value for s in AttackSeverity] else AttackSeverity.HIGH,
        title=f.title,
        description=f.description or "",
        evidence=f.evidence_json or [],
        prevented_by=f.prevented_by or "POLICY_ENGINE",
        mitre_atlas_id=f.mitre_atlas_id or "UNMAPPED",
        owasp_llm_category=f.owasp_llm_id or "UNMAPPED",
        remediation=f.remediation or "",
    )


@router.post("/benchmark/run", response_model=BenchmarkRunSummary)
def run_benchmark_evaluation(
    request: BenchmarkRunRequest,
    db: Session = Depends(get_db),
):
    """
    Executes a comprehensive benchmark evaluation running scenarios across comparative baselines.
    Calculates exact real metrics: prevention rate, false positive rate, accuracy, and latency breakdown.
    """
    baselines = request.baselines or [
        BaselineSystemType.SYSTEM_A_UNPROTECTED,
        BaselineSystemType.SYSTEM_B_STATIC_POLICY,
        BaselineSystemType.SYSTEM_C_POLICY_AND_BEHAVIOR,
        BaselineSystemType.SYSTEM_D_FULL_AGENTSENTINEL,
    ]

    scenarios = default_attack_registry.list_scenarios(
        category=request.category,
        enabled_only=True,
    )

    db_session = db if request.persist_to_db else None
    summary = default_attack_engine.run_comparative_benchmark(
        scenarios=scenarios,
        baselines=baselines,
        db=db_session,
    )

    _benchmark_runs[summary.benchmark_run_id] = summary
    return summary


@router.get("/benchmark", response_model=List[BenchmarkRunSummary])
def list_benchmark_runs():
    """
    Returns history of benchmark evaluations conducted.
    """
    return list(_benchmark_runs.values())


@router.get("/benchmark/{run_id}", response_model=BenchmarkRunSummary)
def get_benchmark_run_detail(run_id: str):
    """
    Retrieves details of a specific benchmark evaluation run.
    """
    if run_id not in _benchmark_runs:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Benchmark run '{run_id}' not found.",
        )
    return _benchmark_runs[run_id]


@router.get("/security/control-effectiveness", response_model=List[ControlEffectivenessRow])
def get_control_effectiveness_matrix(db: Session = Depends(get_db)):
    """
    Generates the comparative control effectiveness matrix across all 17 attack categories
    and 4 baselines, reporting detection rates, prevention rates, and primary defense mechanisms.
    """
    rows = default_attack_engine.evaluate_control_effectiveness(db=db)
    return rows
