"""
AgentSentinel Phase 0.5: Filesystem Security & Sandboxing Layer.
Enforces strict path canonicalization, traversal protection (..), workspace jail boundaries,
symlink escape defenses, and Windows/POSIX system directory protections.
"""

import os
import re
from pathlib import Path
from typing import List, Optional, Tuple
from app.core.logger import logger
from app.execution.config import execution_config


class FilesystemSandbox:
    """
    Validates and jails filesystem access requests to authorized directory trees.
    Canonicalizes all paths before evaluation to defeat traversal, symlink escapes,
    and alternative path representation attacks.
    """

    def __init__(self, workspace_root: Optional[str] = None):
        self.workspace_root = os.path.realpath(workspace_root or execution_config.WORKSPACE_DIR)
        os.makedirs(self.workspace_root, exist_ok=True)

    def canonicalize_path(self, raw_path: str, base_dir: Optional[str] = None) -> str:
        """
        Resolves a raw path into an absolute, normalized, canonical system path.
        Resolves symlinks, relative segments ('..', '.'), and path separators.
        """
        if not raw_path or not isinstance(raw_path, str):
            raise ValueError("Invalid empty path provided.")

        # Check for UNC paths on Windows (e.g. \\server\share or //server/share)
        if raw_path.startswith("\\\\") or raw_path.startswith("//"):
            raise PermissionError("UNC network paths are prohibited by filesystem security policy.")

        target_base = os.path.realpath(base_dir or self.workspace_root)

        # Handle absolute vs relative paths
        if os.path.isabs(raw_path):
            norm_path = os.path.abspath(raw_path)
        else:
            norm_path = os.path.abspath(os.path.join(target_base, raw_path))

        # Resolve symlinks to their true target path (canonicalization)
        canonical = os.path.realpath(norm_path)
        return canonical

    def is_within_directory(self, target_path: str, allowed_root: str) -> bool:
        """
        Verifies that target_path resides strictly within the allowed_root directory tree.
        Prevents traversal and symlink escapes.
        """
        canon_target = os.path.realpath(target_path)
        canon_root = os.path.realpath(allowed_root)

        # Check common path prefix
        try:
            common = os.path.commonpath([canon_target, canon_root])
            return common == canon_root
        except ValueError:
            # On Windows, paths on different drives raise ValueError
            return False

    def validate_read_path(
        self,
        raw_path: str,
        allowed_roots: Optional[List[str]] = None,
        allow_system: bool = False
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Validates whether a path is authorized for reading.
        Returns: (is_allowed, reason, canonical_path)
        """
        try:
            canon = self.canonicalize_path(raw_path)
        except Exception as e:
            return False, f"PATH_CANONICALIZATION_FAILED: {str(e)}", None

        # 1. Check prohibited credential filenames
        basename = os.path.basename(canon).lower()
        canon_clean = canon.lower().replace("\\", "/")
        if any(secret_kw in basename or secret_kw in canon_clean for secret_kw in execution_config.PROHIBITED_SECRET_FILES):
            return False, f"CREDENTIAL_PATH_PROHIBITED: Access to prohibited credential file '{basename}' is blocked.", canon

        canon_lower = canon.lower().replace("/", "\\")

        # 2. Check Windows prohibited system directories
        for sys_dir in execution_config.PROHIBITED_SYSTEM_PATHS_WINDOWS:
            if sys_dir in canon_lower:
                return False, f"SYSTEM_DIRECTORY_PROHIBITED: Access to protected OS directory '{sys_dir}' is blocked.", canon

        # 3. Check POSIX prohibited system directories
        posix_canon = canon.replace("\\", "/")
        for sys_dir in execution_config.PROHIBITED_SYSTEM_PATHS_POSIX:
            if posix_canon.startswith(sys_dir):
                return False, f"SYSTEM_DIRECTORY_PROHIBITED: Access to protected OS directory '{sys_dir}' is blocked.", canon

        # 4. Check allowed roots containment
        roots = allowed_roots if allowed_roots is not None else [self.workspace_root]
        in_any_root = any(self.is_within_directory(canon, root) for root in roots)

        if not in_any_root and not allow_system:
            return False, f"WORKSPACE_TRAVERSAL_BLOCKED: Path '{raw_path}' resolves outside authorized directory roots.", canon

        return True, "Authorized read access", canon

    def validate_write_path(
        self,
        raw_path: str,
        allowed_roots: Optional[List[str]] = None
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Validates whether a path is authorized for writing.
        Enforces strict workspace containment.
        Returns: (is_allowed, reason, canonical_path)
        """
        try:
            canon = self.canonicalize_path(raw_path)
        except Exception as e:
            return False, f"PATH_CANONICALIZATION_FAILED: {str(e)}", None

        # Writes must NEVER target system directories or secret files
        basename = os.path.basename(canon).lower()
        canon_clean = canon.lower().replace("\\", "/")
        if any(secret_kw in basename or secret_kw in canon_clean for secret_kw in execution_config.PROHIBITED_SECRET_FILES):
            return False, f"CREDENTIAL_PATH_PROHIBITED: Writing to prohibited credential file '{basename}' is prohibited.", canon

        roots = allowed_roots if allowed_roots is not None else [self.workspace_root]
        in_any_root = any(self.is_within_directory(canon, root) for root in roots)

        if not in_any_root:
            return False, f"WORKSPACE_ESCAPE_BLOCKED: Write target '{raw_path}' is outside authorized writable workspace.", canon

        return True, "Authorized write access", canon


default_filesystem_sandbox = FilesystemSandbox()
