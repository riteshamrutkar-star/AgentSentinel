from datetime import datetime, timezone
from typing import Any, Dict, List

class BehavioralFeatureExtractor:
    """
    Extracts quantitative behavioral metrics and sequence features from
    an agent session's historical security events.
    """

    @staticmethod
    def extract_features(events: List[Any], current_tool_name: str, current_role: str) -> Dict[str, float]:
        """
        Extracts numerical behavioral features from historical session events and current request.
        `events` can be a list of EventModel OR SecurityEvent objects.
        """
        total_events = len(events) + 1  # Including current event
        denied_count = 0
        sensitive_count = 0
        burst_count = 0
        transition_penalty = 0.0

        tool_sequence = []
        timestamps = []

        sensitive_keywords = [".ssh", "id_rsa", "shadow", "passwd", ".env", "credentials", "private_key", "drop_table", "delete_all"]

        for idx, evt in enumerate(events):
            # Extract tool name & decision result
            t_name = getattr(evt, 'tool_name', None) or (evt.tool_action.tool_name if hasattr(evt, 'tool_action') else "")
            d_result = getattr(evt, 'decision_result', None) or (evt.decision_context.decision_result if hasattr(evt, 'decision_context') else "")
            t_resource = getattr(evt, 'target_resource', None) or (evt.tool_action.target_resource if hasattr(evt, 'tool_action') else "")
            t_stamp = getattr(evt, 'timestamp', None) or (evt.task_context.timestamp if hasattr(evt, 'task_context') else None)

            tool_sequence.append(t_name.lower())

            if d_result in ("DENY", "BLOCK", "REJECTED"):
                denied_count += 1

            if any(kw in t_resource.lower() or kw in t_name.lower() for kw in sensitive_keywords):
                sensitive_count += 1

            if t_stamp:
                if isinstance(t_stamp, str):
                    try:
                        dt = datetime.fromisoformat(t_stamp.replace('Z', '+00:00'))
                        timestamps.append(dt)
                    except Exception:
                        pass
                elif isinstance(t_stamp, datetime):
                    timestamps.append(t_stamp)

        # Append current call info
        tool_sequence.append(current_tool_name.lower())
        if any(kw in current_tool_name.lower() for kw in sensitive_keywords):
            sensitive_count += 1

        # Calculate burst rate (< 1.5 second gaps between consecutive tool calls)
        if len(timestamps) > 1:
            for i in range(1, len(timestamps)):
                diff_sec = abs((timestamps[i] - timestamps[i-1]).total_seconds())
                if diff_sec < 1.5:
                    burst_count += 1

        # Sequence transition analysis (e.g. read/search -> read_file -> privileged_access)
        seq_str = " -> ".join(tool_sequence)
        if "search" in seq_str and ("read_file" in seq_str or "read_system_file" in seq_str) and any(kw in seq_str for kw in sensitive_keywords):
            transition_penalty += 0.40
        if denied_count >= 2:
            transition_penalty += 0.30

        # Role / Tool Mismatch indicator
        role_mismatch = 0.0
        c_role = current_role.lower()
        if "research" in c_role and ("write_file" in current_tool_name.lower() or "exec" in current_tool_name.lower() or "drop" in current_tool_name.lower()):
            role_mismatch = 0.35
        elif "code" in c_role and ("drop_table" in current_tool_name.lower() or "delete_all" in current_tool_name.lower()):
            role_mismatch = 0.40

        ratio_denied = (denied_count / max(total_events, 1))

        return {
            "sequence_length": float(total_events),
            "denied_count": float(denied_count),
            "sensitive_action_count": float(sensitive_count),
            "burst_count": float(burst_count),
            "ratio_denied": float(round(ratio_denied, 3)),
            "transition_penalty": float(round(transition_penalty, 3)),
            "role_mismatch": float(round(role_mismatch, 3)),
        }
