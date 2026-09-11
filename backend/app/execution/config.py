"""
AgentSentinel Phase 0.5: Secure Execution & Sandboxing Configuration.
Defines execution limits, sandbox profiles, path boundaries, network egress rules,
executable allowlists, and secret detection regex patterns.
"""

import os
from typing import Dict, List
from app.execution.models import SandboxMode, SandboxProfile


class ExecutionConfig:
    """Centralized execution security configuration."""

    # Timeouts & Resource Quotas
    DEFAULT_TIMEOUT_SECONDS: float = 10.0
    MAX_TIMEOUT_SECONDS: float = 60.0
    MAX_INPUT_BYTES: int = 65_536        # 64 KB
    MAX_OUTPUT_BYTES: int = 1_048_576    # 1 MB
    DEFAULT_MEMORY_LIMIT_MB: int = 256

    # Filesystem Sandboxing
    WORKSPACE_DIR: str = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "workspace")
    )
    
    PROHIBITED_SYSTEM_PATHS_WINDOWS: List[str] = [
        "c:\\windows",
        "c:\\program files",
        "c:\\program files (x86)",
        "\\system32",
        "\\config\\sam",
        "\\config\\security",
        "\\config\\system",
    ]

    PROHIBITED_SYSTEM_PATHS_POSIX: List[str] = [
        "/etc",
        "/root",
        "/proc",
        "/sys",
        "/dev",
        "/var/run",
        "/boot",
    ]

    PROHIBITED_SECRET_FILES: List[str] = [
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "known_hosts",
        "shadow",
        "master.passwd",
        ".bash_history",
        ".zsh_history",
        ".env",
        ".aws/credentials",
    ]

    # Network Egress Controls
    ALLOWED_SEARCH_DOMAINS: List[str] = [
        "google.com",
        "www.google.com",
        "bing.com",
        "www.bing.com",
        "fastapi.tiangolo.com",
        "python.org",
        "www.python.org",
        "wikipedia.org",
        "github.com",
    ]

    BLOCKED_EGRESS_PATTERNS: List[str] = [
        "webhook.site",
        "requestbin",
        "pastebin.com",
        "ngrok.io",
        "burpcollaborator.net",
        "canarytokens.com",
        "169.254.169.254",  # Cloud instance metadata service
    ]

    # Process Execution Controls
    ALLOWED_EXECUTABLES: List[str] = [
        "python",
        "python.exe",
        "pytest",
        "git",
        "git.exe",
        "echo",
        "dir",
        "ls",
        "node",
        "node.exe",
        "npm",
    ]

    # Common Secret Detection Patterns
    SECRET_PATTERNS: Dict[str, str] = {
        "PRIVATE_KEY": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        "OPENAI_API_KEY": r"sk-[a-zA-Z0-9_-]{20,}",
        "AWS_ACCESS_KEY": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "GITHUB_TOKEN": r"gh[pousr]_[A-Za-z0-9_]{36,}",
        "JWT_TOKEN": r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
        "BEARER_TOKEN": r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}",
        "DB_CONNECTION_STRING": r"(?i)(?:postgres(?:ql)?|mysql|mongodb)://[^:]+:[^@]+@[^/:]+(?::\d+)?/[^\s]+",
        "PASSWORD_ASSIGNMENT": r"(?i)(?:password|passwd|pwd|secret)\s*[:=]\s*['\"][^\s'\"]{6,}['\"]",
    }

    # Standard Predefined Sandbox Profiles
    @classmethod
    def get_standard_profiles(cls) -> Dict[str, SandboxProfile]:
        """Returns standard predefined sandbox configurations."""
        return {
            "STRICT": SandboxProfile(
                name="STRICT",
                mode=SandboxMode.STRICT,
                readable_paths=[cls.WORKSPACE_DIR],
                writable_paths=[],
                network_allowed=False,
                process_execution_allowed=False,
                max_timeout_seconds=5.0,
                max_memory_mb=128,
            ),
            "STANDARD": SandboxProfile(
                name="STANDARD",
                mode=SandboxMode.STANDARD,
                readable_paths=[cls.WORKSPACE_DIR],
                writable_paths=[cls.WORKSPACE_DIR],
                network_allowed=False,
                process_execution_allowed=False,
                max_timeout_seconds=10.0,
                max_memory_mb=256,
            ),
            "RESEARCH": SandboxProfile(
                name="RESEARCH",
                mode=SandboxMode.RESEARCH,
                readable_paths=[cls.WORKSPACE_DIR],
                writable_paths=[cls.WORKSPACE_DIR],
                network_allowed=True,
                allowed_domains=cls.ALLOWED_SEARCH_DOMAINS,
                blocked_domains=cls.BLOCKED_EGRESS_PATTERNS,
                process_execution_allowed=False,
                max_timeout_seconds=15.0,
                max_memory_mb=256,
            ),
            "DEVELOPER": SandboxProfile(
                name="DEVELOPER",
                mode=SandboxMode.DEVELOPER,
                readable_paths=[cls.WORKSPACE_DIR],
                writable_paths=[cls.WORKSPACE_DIR],
                network_allowed=False,
                process_execution_allowed=True,
                allowed_executables=cls.ALLOWED_EXECUTABLES,
                max_timeout_seconds=20.0,
                max_memory_mb=512,
            ),
            "PRIVILEGED": SandboxProfile(
                name="PRIVILEGED",
                mode=SandboxMode.PRIVILEGED,
                readable_paths=[cls.WORKSPACE_DIR],
                writable_paths=[cls.WORKSPACE_DIR],
                network_allowed=False,
                process_execution_allowed=False,
                max_timeout_seconds=30.0,
                max_memory_mb=512,
            ),
        }


execution_config = ExecutionConfig()
