"""
Behavioral Feature Engine for AgentSentinel.
Extracts rich, normalized quantitative and structural behavioral features
from historical session events and the current tool call request.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from app.anomaly.config import behavioral_config
from app.events.model import SecurityEvent

class BehavioralFeatureEngine:
    """
    Modular feature extraction engine converting raw session history and
    the current SecurityEvent into structured behavioral metrics.
    """

    @staticmethod
    def extract_features(
        history: Optional[List[Any]],
        current_event: SecurityEvent
    ) -> Dict[str, Any]:
        """
        Extracts comprehensive behavioral feature dictionary.
        `history` can be a list of EventModel OR SecurityEvent objects or None.
        """
        history_list = history or []
        total_events = len(history_list) + 1  # Including current event

        curr_tool = current_event.tool_action.tool_name.lower().strip()
        curr_role = current_event.identity.role.lower().strip()
        curr_action_type = (
            current_event.tool_action.action_type.value
            if hasattr(current_event.tool_action.action_type, "value")
            else str(current_event.tool_action.action_type).upper()
        )
        curr_resource = str(current_event.tool_action.target_resource or "").lower()

        denied_count = 0
        approval_count = 0
        sensitive_count = 0
        tool_sequence: List[str] = []
        timestamps: List[datetime] = []
        action_types: List[str] = []
        decisions: List[str] = []

        # Normalize history to chronological order (oldest -> newest)
        def _extract_ts(e):
            if e is None:
                return None
            t = getattr(e, "timestamp", None)
            if t is None and hasattr(e, "task_context"):
                t = getattr(e.task_context, "timestamp", None)
            if isinstance(t, str):
                try:
                    dt = datetime.fromisoformat(t.replace("Z", "+00:00"))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt
                except Exception:
                    return None
            elif isinstance(t, datetime):
                if t.tzinfo is None:
                    t = t.replace(tzinfo=timezone.utc)
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

        # Parse history
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
            a_type = getattr(evt, "action_type", None) or (
                evt.tool_action.action_type.value if hasattr(evt, "tool_action") and hasattr(evt.tool_action.action_type, "value") else str(getattr(getattr(evt, "tool_action", None), "action_type", ""))
            )
            t_stamp = getattr(evt, "timestamp", None) or (
                evt.task_context.timestamp if hasattr(evt, "task_context") else None
            )

            t_name_str = str(t_name or "").lower().strip()
            tool_sequence.append(t_name_str)
            action_types.append(str(a_type or "").upper())

            dec_str = str(d_result or "").upper()
            decisions.append(dec_str)

            if dec_str in ("DENY", "BLOCK", "REJECTED"):
                denied_count += 1
            elif dec_str in ("REQUIRE_APPROVAL", "APPROVED"):
                approval_count += 1

            if any(kw in str(t_resource).lower() or kw in t_name_str for kw in behavioral_config.SENSITIVE_RESOURCE_KEYWORDS):
                sensitive_count += 1

            if t_stamp:
                if isinstance(t_stamp, str):
                    try:
                        dt = datetime.fromisoformat(t_stamp.replace("Z", "+00:00"))
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        timestamps.append(dt)
                    except Exception:
                        pass
                elif isinstance(t_stamp, datetime):
                    if t_stamp.tzinfo is None:
                        t_stamp = t_stamp.replace(tzinfo=timezone.utc)
                    timestamps.append(t_stamp)

        # Append current event
        tool_sequence.append(curr_tool)
        action_types.append(curr_action_type)

        curr_is_sensitive = any(
            kw in curr_resource or kw in curr_tool
            for kw in behavioral_config.SENSITIVE_RESOURCE_KEYWORDS
        )
        if curr_is_sensitive:
            sensitive_count += 1

        curr_time = datetime.now(timezone.utc)
        timestamps.append(curr_time)

        # Calculate interval and burst metrics
        intervals_sec: List[float] = []
        burst_events_count = 0
        calls_last_minute = 1

        if len(timestamps) > 1:
            for i in range(1, len(timestamps)):
                gap = abs((timestamps[i] - timestamps[i - 1]).total_seconds())
                intervals_sec.append(gap)
                if gap <= behavioral_config.BURST_WINDOW_SECONDS:
                    burst_events_count += 1

            # Count calls in last 60 seconds
            latest_time = timestamps[-1]
            calls_last_minute = sum(
                1 for ts in timestamps if abs((latest_time - ts).total_seconds()) <= behavioral_config.HIGH_FREQUENCY_WINDOW_SECONDS
            )

        min_interval = min(intervals_sec) if intervals_sec else 999.0
        avg_interval = sum(intervals_sec) / len(intervals_sec) if intervals_sec else 999.0

        # Calculate consecutive identical tool repeats at end of sequence
        repeat_tool_count = 1
        for tool in reversed(tool_sequence[:-1]):
            if tool == curr_tool:
                repeat_tool_count += 1
            else:
                break

        # Previous tool and transition pair
        previous_tool = tool_sequence[-2] if len(tool_sequence) >= 2 else None
        transition_pair = (previous_tool, curr_tool) if previous_tool else None

        # Check role-capability compatibility
        allowed_scopes = behavioral_config.ROLE_CAPABILITY_SCOPES.get(curr_role, {"READ", "NETWORK"})
        role_action_allowed = curr_action_type in allowed_scopes or curr_action_type == "UNKNOWN"

        prohibited_tools = behavioral_config.ROLE_PROHIBITED_TOOLS.get(curr_role, [])
        role_prohibited_match = curr_tool in prohibited_tools

        # Consecutive blocks at end of history
        consecutive_blocks = 0
        for d in reversed(decisions):
            if d in ("DENY", "BLOCK", "REJECTED"):
                consecutive_blocks += 1
            else:
                break

        ratio_denied = denied_count / max(total_events, 1)

        return {
            "sequence_length": total_events,
            "tool_sequence": tool_sequence,
            "action_types": action_types,
            "current_tool": curr_tool,
            "previous_tool": previous_tool,
            "transition_pair": transition_pair,
            "current_role": curr_role,
            "current_action_type": curr_action_type,
            "current_is_sensitive": curr_is_sensitive,
            "sensitive_action_count": sensitive_count,
            "denied_count": denied_count,
            "approval_count": approval_count,
            "consecutive_blocks": consecutive_blocks,
            "ratio_denied": round(ratio_denied, 3),
            "burst_events_count": burst_events_count,
            "min_interval_seconds": round(min_interval, 2),
            "average_interval_seconds": round(avg_interval, 2),
            "calls_last_minute": calls_last_minute,
            "repeat_tool_count": repeat_tool_count,
            "role_action_allowed": role_action_allowed,
            "role_prohibited_match": role_prohibited_match,
        }
