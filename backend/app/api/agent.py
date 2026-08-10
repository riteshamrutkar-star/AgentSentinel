from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.agent.runner import LangChainAgentRunner
from app.agent.scenarios import get_demo_agent_scenarios
from app.db.session import get_db

router = APIRouter(prefix="/api/v1/agent", tags=["LangChain Real Agent Integration"])

class AgentTaskExecutionRequest(BaseModel):
    scenario_id: Optional[str] = Field(None, description="Preset scenario ID (e.g., SAFE_RESEARCH, BLOCKED_CREDENTIAL_ACCESS, RISKY_DB_DROP)")
    session_id: str = Field(..., description="Agent session identifier")
    agent_id: str = Field("agent_langchain_v1", description="Agent ID")
    user_id: str = Field("user_alice", description="User ID")
    role: str = Field("research_assistant", description="Agent role (research_assistant, code_assistant, database_admin)")
    task: str = Field(..., description="User task description")
    tool_name: Optional[str] = Field(None, description="Optional explicit tool to invoke")
    tool_input: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Optional tool parameters")

@router.get("/scenarios", summary="List Benchmark Agent Scenarios")
async def list_scenarios():
    """Returns list of benchmark demonstration scenarios for testing real agent integration."""
    return get_demo_agent_scenarios()

@router.post("/run", summary="Run LangChain Agent Task Through AgentSentinel")
async def run_agent_task(
    request: AgentTaskExecutionRequest,
    db: Session = Depends(get_db)
):
    """
    Executes a LangChain Agent task while mediating 100% of tool calls through
    the AgentSentinel runtime security control plane.
    """
    runner = LangChainAgentRunner(
        session_id=request.session_id,
        agent_id=request.agent_id,
        user_id=request.user_id,
        role=request.role,
        framework_name="LangChain",
    )

    # If preset scenario selected, execute its defined steps
    scenarios = {s["scenario_id"]: s for s in get_demo_agent_scenarios()}
    if request.scenario_id and request.scenario_id in scenarios:
        scenario = scenarios[request.scenario_id]
        runner.role = scenario.get("role", runner.role)
        results = []
        for step in scenario["steps"]:
            res = runner.execute_tool_action(
                tool_name=step["tool_name"],
                tool_input=step["tool_input"],
                task_summary=scenario["task"],
                db=db,
            )
            results.append(res)

        return {
            "status": "success",
            "scenario_id": request.scenario_id,
            "session_id": request.session_id,
            "agent_id": runner.agent_id,
            "role": runner.role,
            "task": scenario["task"],
            "step_results": results,
        }

    # Execute custom single tool step
    if not request.tool_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either 'scenario_id' or 'tool_name' must be provided."
        )

    res = runner.execute_tool_action(
        tool_name=request.tool_name,
        tool_input=request.tool_input or {},
        task_summary=request.task,
        db=db,
    )

    return {
        "status": "success",
        "session_id": request.session_id,
        "agent_id": runner.agent_id,
        "role": runner.role,
        "task": request.task,
        "step_results": [res],
    }
