"""
Session and Agent Behavioral Baseline Engine for AgentSentinel.
Captures normal operational profiles from historical activity and evaluates
behavioral deviation for incoming tool invocations.
"""

from collections import Counter
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from app.anomaly.config import behavioral_config
from app.events.model import SecurityEvent

class SessionBaseline(BaseModel):
    """Encapsulates the observed normal behavioral profile for an agent session."""
    session_id: str
    agent_id: str
    role: str
    total_events: int = 0
    is_established: bool = False
    common_tools: Dict[str, int] = Field(default_factory=dict)
    average_call_interval_sec: float = 0.0
    typical_sensitivity_ratio: float = 0.0
    typical_failure_ratio: float = 0.0

class SessionBaselineEngine:
    """
    Constructs behavioral baselines from session event history and calculates
    quantitative deviation metrics for prospective tool calls.
    """

    @staticmethod
    def build_baseline(
        session_id: str,
        agent_id: str,
        role: str,
        history: Optional[List[Any]]
    ) -> SessionBaseline:
        """Constructs a SessionBaseline from historical event records."""
        history_list = history or []
        total = len(history_list)

        if total < behavioral_config.BASELINE_MIN_EVENTS:
            # Baseline not yet established (cold start)
            return SessionBaseline(
                session_id=session_id,
                agent_id=agent_id,
                role=role,
                total_events=total,
                is_established=False,
            )

        tool_counts: Counter = Counter()
        sensitive_count = 0
        failure_count = 0
        intervals: List[float] = []
        timestamps: List[datetime] = []

        # Normalize history to chronological order (oldest -> newest)
        def _extract_ts(e):
            if e is None:
                return None
            t = getattr(e, "timestamp", None)
            if t is None and hasattr(e, "task_context"):
                t = getattr(e.task_context, "timestamp", None)
            if isinstance(t, str):
                try:
                    return datetime.fromisoformat(t.replace("Z", "+00:00"))
                except Exception:
                    return None
            elif isinstance(t, datetime):
                return t
            return None

        clean_history = [e for e in history_list if e is not None]
        has_ts = any(_extract_ts(e) is not None for e in clean_history)
        if has_ts:
            ordered_history = sorted(
                clean_history,
                key=lambda e: _extract_ts(e) or datetime.min.replace(tzinfo=timezone.utc)
            )
        else:
            ordered_history = list(reversed(clean_history))

        for evt in ordered_history:

            t_name = getattr(evt, "tool_name", None) or (
                evt.tool_action.tool_name if hasattr(evt, "tool_action") else ""
            )
            d_result = getattr(evt, "decision_result", None) or (
                evt.decision_context.decision_result if hasattr(evt, "decision_context") else ""
            )
            t_resource = getattr(evt, "target_resource", None) or (
                evt.tool_action.target_resource if hasattr(evt, "tool_action") else ""
            )
            t_stamp = getattr(evt, "timestamp", None) or (
                evt.task_context.timestamp if hasattr(evt, "task_context") else None
            )

            if t_name:
                tool_counts[str(t_name).lower().strip()] += 1

            if any(kw in str(t_resource).lower() or kw in str(t_name).lower() for kw in behavioral_config.SENSITIVE_RESOURCE_KEYWORDS):
                sensitive_count += 1

            if str(d_result).upper() in ("DENY", "BLOCK", "REJECTED"):
                failure_count += 1

            if t_stamp:
                if isinstance(t_stamp, str):
                    try:
                        dt = datetime.fromisoformat(t_stamp.replace("Z", "+00:00"))
                        timestamps.append(dt)
                    except Exception:
                        pass
                elif isinstance(t_stamp, datetime):
                    timestamps.append(t_stamp)

        if len(timestamps) > 1:
            for i in range(1, len(timestamps)):
                gap = abs((timestamps[i] - timestamps[i - 1]).total_seconds())
                intervals.append(gap)

        avg_interval = sum(intervals) / len(intervals) if intervals else 5.0
        sens_ratio = sensitive_count / max(total, 1)
        fail_ratio = failure_count / max(total, 1)

        return SessionBaseline(
            session_id=session_id,
            agent_id=agent_id,
            role=role,
            total_events=total,
            is_established=True,
            common_tools=dict(tool_counts),
            average_call_interval_sec=round(avg_interval, 2),
            typical_sensitivity_ratio=round(sens_ratio, 2),
            typical_failure_ratio=round(fail_ratio, 2),
        )

    @staticmethod
    def calculate_deviation(
        current_event: SecurityEvent,
        baseline: SessionBaseline
    ) -> Dict[str, float]:
        """Calculates deviation metrics between incoming event and established session baseline."""
        if not baseline.is_established:
            return {
                "baseline_established": 0.0,
                "unusual_tool_deviation": 0.0,
                "sensitivity_deviation": 0.0,
                "composite_deviation": 0.0,
            }

        curr_tool = current_event.tool_action.tool_name.lower().strip()
        curr_resource = str(current_event.tool_action.target_resource or "").lower()
        curr_args_str = str(current_event.tool_action.arguments_payload or "").lower()

        # Tool deviation: 1.0 if tool was never observed in established session baseline
        unusual_tool = 1.0 if curr_tool not in baseline.common_tools else 0.0

        # Sensitivity deviation: 1.0 if event touches sensitive resources when baseline has <= 10% sensitivity
        curr_is_sensitive = any(
            kw in curr_resource or kw in curr_tool or kw in curr_args_str
            for kw in behavioral_config.SENSITIVE_RESOURCE_KEYWORDS
        )
        sensitivity_dev = 1.0 if (curr_is_sensitive and baseline.typical_sensitivity_ratio <= 0.10) else 0.0

        # Composite deviation score
        composite = (unusual_tool * 0.50) + (sensitivity_dev * 0.50)

        return {
            "baseline_established": 1.0,
            "unusual_tool_deviation": unusual_tool,
            "sensitivity_deviation": sensitivity_dev,
            "composite_deviation": round(composite, 3),
        }

# Global baseline engine instance
default_baseline_engine = SessionBaselineEngine()
