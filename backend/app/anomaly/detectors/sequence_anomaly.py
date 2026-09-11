"""
Sequence Anomaly Detector for AgentSentinel.
Recognizes multi-step suspicious, probing, reconnaissance, and exfiltration
chains across chronological tool invocation sequences.
"""

from typing import Any, Dict, List, Optional
from app.anomaly.base import BehavioralDetector, DetectorResult
from app.anomaly.config import behavioral_config
from app.events.model import SecurityEvent

class SequenceAnomalyDetector(BehavioralDetector):
    """
    Transparent, rule-based sequence detector analyzing multi-event patterns:
    - Reconnaissance followed by credential access and exfiltration
    - Harmless queries followed by destructive mutations
    - Repeated denials followed by escalating privileged probes
    """

    @property
    def name(self) -> str:
        return "SequenceAnomalyDetector"

    @property
    def weight(self) -> float:
        return behavioral_config.WEIGHT_SEQUENCE

    @property
    def description(self) -> str:
        return "Evaluates chronological tool chains to detect reconnaissance-to-exfiltration, recon-before-destruction, and privilege escalation."

    def detect(
        self,
        event: SecurityEvent,
        history: List[Any],
        context: Optional[Dict[str, Any]] = None
    ) -> DetectorResult:
        ctx = context or {}
        features = ctx.get("features", {})
        tool_seq = features.get("tool_sequence", [event.tool_action.tool_name.lower()])
        curr_tool = event.tool_action.tool_name.lower().strip()
        curr_resource = str(event.tool_action.target_resource or "").lower()
        curr_is_sensitive = features.get("current_is_sensitive", False)
        denied_count = int(features.get("denied_count", 0))
        consecutive_blocks = int(features.get("consecutive_blocks", 0))

        score = 0.05
        evidence: List[str] = []
        matched_pattern = None

        seq_str = " -> ".join(tool_seq)

        # Pattern 1: PROBE_TO_EXFILTRATE
        # (search or read) -> (system file / credentials) -> (write or network)
        has_recon = any(t in seq_str for t in ["search", "workspace", "list"])
        has_cred = any(kw in seq_str for kw in [".ssh", "id_rsa", "shadow", "passwd", "read_system_file"])
        has_exfil = any(t in curr_tool for t in ["write", "network", "upload", "send"])

        if has_recon and has_cred and (has_exfil or curr_is_sensitive):
            score = max(score, 0.95)
            matched_pattern = "PROBE_TO_EXFILTRATE_SEQUENCE"
            evidence.append(f"Attack chain detected: Reconnaissance followed by credential access and write/exfiltration ('{seq_str}')")

        # Pattern 2: RECON_BEFORE_DESTRUCTION
        # Recon tools followed suddenly by destructive database drop
        if has_recon and ("drop" in curr_tool or "delete" in curr_tool or "truncate" in curr_tool):
            score = max(score, 0.90)
            matched_pattern = "RECON_BEFORE_DESTRUCTION"
            evidence.append(f"Reconnaissance-to-destruction pattern: Benign queries abruptly transitioned into destructive operation ('{curr_tool}')")

        # Pattern 3: READ_WRITE_EXEC
        if len(tool_seq) >= 3:
            types = features.get("action_types", [])
            if len(types) >= 3:
                last_3_types = [str(t).upper() for t in types[-3:]]
                if last_3_types == ["READ", "WRITE", "EXECUTE"]:
                    score = max(score, 0.85)
                    matched_pattern = "READ_WRITE_EXEC_PIPELINE"
                    evidence.append("Read-Write-Execute sequence detected: File stage followed immediately by execution")

        # Pattern 4: PROGRESSIVE_PRIVILEGE_ESCALATION
        # History contains multiple blocks and current action is another sensitive probe
        if (denied_count >= 2 or consecutive_blocks >= 2) and (curr_is_sensitive or "system" in curr_tool or "admin" in curr_tool):
            score = max(score, 0.90)
            matched_pattern = "PROGRESSIVE_PRIVILEGE_ESCALATION"
            evidence.append(f"Progressive privilege escalation: {denied_count} prior blocked actions followed by sensitive access attempt on '{curr_tool}'")

        # Pattern 5: SENSITIVE_PROBING_ESCALATION (e.g. search -> read_system_file)
        if len(tool_seq) >= 2 and not matched_pattern:
            prev_tool = features.get("previous_tool", "")
            if prev_tool in ["google_search", "read_workspace_file"] and ("system" in curr_tool or curr_is_sensitive):
                score = max(score, 0.75)
                matched_pattern = "SENSITIVE_PROBING_TRANSITION"
                evidence.append(f"Suspicious sequence escalation: '{prev_tool}' transitioned directly to sensitive action '{curr_tool}'")

        clamped_score = min(1.0, max(0.0, score))
        confidence = min(1.0, 0.40 + (len(tool_seq) * 0.15))

        if matched_pattern:
            explanation = f"Sequence Anomaly [{matched_pattern}]: {'; '.join(evidence)}"
        else:
            explanation = "Tool execution sequence follows standard, non-malicious operational patterns."

        return DetectorResult.create(
            detector_name=self.name,
            score=clamped_score,
            explanation=explanation,
            evidence=evidence,
            confidence=confidence,
            metadata={"matched_pattern": matched_pattern, "sequence_length": len(tool_seq), "sequence": seq_str},
        )
