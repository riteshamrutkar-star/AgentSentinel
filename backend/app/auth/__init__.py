"""
AgentSentinel Phase 0.8: Authentication & Administrative RBAC Package.
Provides centralized API credential handling, role-based authorization,
and auditable administrative identity management.
"""

from app.auth.models import AdminRole, AuthenticatedIdentity
from app.auth.service import AuthService, auth_service
from app.auth.dependencies import get_current_identity, require_role

__all__ = [
    "AdminRole",
    "AuthenticatedIdentity",
    "AuthService",
    "auth_service",
    "get_current_identity",
    "require_role",
]