"""
AgentSentinel Phase 0.5: Process Execution Security Layer.
Enforces executable allowlists, argument array validation, working directory jail,
command injection prevention, timeout limits, and shell=False execution.
"""

import os
import shlex
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple
from app.core.logger import logger
from app.execution.config import execution_config
from app.execution.filesystem import default_filesystem_sandbox


class ProcessExecutionGuard:
    """
    Validates, bounds, and safely executes external commands.
    Strictly forbids arbitrary shell invocation (shell=True) and command chaining.
    """

    DANGEROUS_TOKENS: List[str] = [
        "&&", "||", ";", "|", "`", "$(", "${", ">", ">>", "<", "&", "\n", "\r"
    ]

    def __init__(self, allowed_executables: Optional[List[str]] = None):
        self.allowed_executables = set(
            allowed_executables or execution_config.ALLOWED_EXECUTABLES
        )

    def validate_command(
        self,
        command: Any,
        working_dir: Optional[str] = None,
        process_allowed: bool = False,
    ) -> Tuple[bool, Optional[str], List[str]]:
        """
        Validates command structure, executable name, and argument safety.
        Returns (is_valid, rejection_reason, argument_list).
        """
        # 1. Verify profile permits process execution
        if not process_allowed:
            return False, "PROCESS_EXECUTION_PROHIBITED: Current sandbox profile does not permit subprocess execution.", []

        # Parse command to list of tokens
        if isinstance(command, str):
            # Check for dangerous shell metacharacters before splitting
            for tok in self.DANGEROUS_TOKENS:
                if tok in command:
                    return False, f"COMMAND_INJECTION_DETECTED: Prohibited shell token '{tok}' found in command string.", []
            try:
                args = shlex.split(command, posix=False if os.name == "nt" else True)
            except Exception as e:
                return False, f"COMMAND_PARSING_FAILED: Could not safely tokenize command: {e}", []
        elif isinstance(command, list):
            args = [str(a) for a in command]
            # Check each argument for injection tokens
            for arg in args:
                for tok in self.DANGEROUS_TOKENS:
                    if tok in arg:
                        return False, f"COMMAND_INJECTION_DETECTED: Prohibited shell token '{tok}' found in argument '{arg}'.", []
        else:
            return False, "INVALID_COMMAND_FORMAT: Command must be a string or list of argument strings.", []

        if not args:
            return False, "EMPTY_COMMAND: No executable specified in command.", []

        executable = os.path.basename(args[0]).lower()

        # 2. Enforce executable allowlist
        if executable not in self.allowed_executables:
            return False, f"UNAUTHORIZED_EXECUTABLE_BLOCKED: Executable '{executable}' is not in the authorized process allowlist.", []

        # 3. Validate working directory
        if working_dir:
            try:
                canon_cwd = default_filesystem_sandbox.canonicalize_path(working_dir)
                if not default_filesystem_sandbox.is_within_directory(canon_cwd, default_filesystem_sandbox.workspace_root):
                    return False, f"WORKING_DIR_ESCAPE_BLOCKED: Working directory '{working_dir}' is outside authorized workspace.", []
            except Exception as e:
                return False, f"WORKING_DIR_VALIDATION_FAILED: {e}", []

        return True, None, args

    def execute_process(
        self,
        args: List[str],
        working_dir: Optional[str] = None,
        timeout_seconds: float = 10.0,
        max_output_bytes: int = 1_048_576,
    ) -> Tuple[int, str, float]:
        """
        Executes a validated command via subprocess.run with shell=False.
        Returns (exit_code, output_text, elapsed_ms).
        """
        cwd = working_dir or default_filesystem_sandbox.workspace_root
        start_time = time.perf_counter()

        try:
            completed = subprocess.run(
                args,
                cwd=cwd,
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            stdout = completed.stdout or ""
            stderr = completed.stderr or ""
            output = stdout + (f"\nSTDERR:\n{stderr}" if stderr else "")

            # Truncate if exceeds output limit
            if len(output.encode("utf-8")) > max_output_bytes:
                output = output[:max_output_bytes] + "\n[OUTPUT_TRUNCATED: Exceeded maximum permitted byte limit]"

            return completed.returncode, output, elapsed_ms

        except subprocess.TimeoutExpired:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.warning(f"Process timed out after {timeout_seconds}s: {args}")
            raise TimeoutError(f"Process execution timed out after {timeout_seconds} seconds.")

        except Exception as e:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.error(f"Error during subprocess execution: {e}", exc_info=True)
            raise


default_process_guard = ProcessExecutionGuard()
