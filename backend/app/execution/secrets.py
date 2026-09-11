"""
AgentSentinel Phase 0.5: Secret Protection & Redaction Layer.
Detects sensitive credentials, tokens, API keys, private keys, and passwords
in tool arguments and execution outputs. Performs automated redaction before audit persistence.
"""

import re
from typing import Any, Dict, List, Tuple
from app.core.logger import logger
from app.execution.config import execution_config
from app.execution.models import SecretRedactionResult


class SecretProtectionLayer:
    """
    Scans, detects, and redacts sensitive credentials and secrets
    from execution input arguments and output buffers.
    """

    def __init__(self, custom_patterns: Dict[str, str] = None):
        patterns = custom_patterns or execution_config.SECRET_PATTERNS
        self.compiled_patterns: Dict[str, re.Pattern] = {
            name: re.compile(pat) for name, pat in patterns.items()
        }

    def detect_secrets(self, text: str) -> List[Tuple[str, str]]:
        """
        Scans text for known secret patterns.
        Returns list of (pattern_name, masked_sample) tuples.
        """
        if not text or not isinstance(text, str):
            return []

        detected = []
        for name, pattern in self.compiled_patterns.items():
            matches = pattern.finditer(text)
            for m in matches:
                val = m.group(0)
                # Show only first 3 and last 2 characters in log sample for explanation
                if len(val) > 8:
                    masked = f"{val[:3]}...{val[-2:]}"
                else:
                    masked = "***"
                detected.append((name, masked))

        return detected

    def redact_secrets(self, text: str) -> SecretRedactionResult:
        """
        Replaces all detected secrets in the input text with '[REDACTED_<TYPE>]'.
        Returns structured SecretRedactionResult.
        """
        if not text or not isinstance(text, str):
            return SecretRedactionResult(
                sanitized_text=str(text or ""),
                redacted=False,
                detected_secrets=[],
            )

        sanitized = text
        detected_types: List[str] = []

        for name, pattern in self.compiled_patterns.items():
            if pattern.search(sanitized):
                detected_types.append(name)
                sanitized = pattern.sub(f"[REDACTED_{name}]", sanitized)

        was_redacted = len(detected_types) > 0
        if was_redacted:
            logger.info(f"SecretProtectionLayer redacted {len(detected_types)} secret(s): {detected_types}")

        return SecretRedactionResult(
            sanitized_text=sanitized,
            redacted=was_redacted,
            detected_secrets=detected_types,
        )

    def sanitize_payload(self, payload: Any) -> Any:
        """
        Recursively sanitizes a dictionary, list, or primitive,
        redacting any string values containing secrets.
        """
        if isinstance(payload, dict):
            return {k: self.sanitize_payload(v) for k, v in payload.items()}
        elif isinstance(payload, list):
            return [self.sanitize_payload(item) for item in payload]
        elif isinstance(payload, str):
            res = self.redact_secrets(payload)
            return res.sanitized_text
        return payload

    def should_block_on_secret(self, text: str) -> bool:
        """
        Determines if an output contains critical exfiltration secrets
        (e.g., raw private keys or cloud admin credentials) that should block delivery.
        """
        detected = [name for name, _ in self.detect_secrets(text)]
        return any(t in detected for t in ["PRIVATE_KEY", "AWS_ACCESS_KEY", "DB_CONNECTION_STRING"])


default_secret_protector = SecretProtectionLayer()
