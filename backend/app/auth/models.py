"""
AgentSentinel Phase 0.8: Authentication & Administrative RBAC Domain Models.
Distinguishes Human/Operator administrative roles from Agent/Tool authorization.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AdminRole(str, Enum):
    """
    Administrative operator roles for AgentSentinel platform access.
    Hierarchical: VIEWER < OPERATOR < SECURITY_ADMIN < PLATFORM_ADMIN.
    """
    VIEWER = "VIEWER"
    OPERATOR = "OPERATOR"
    SECURITY_ADMIN = "SECURITY_ADMIN"
    PLATFORM_ADMIN = "PLATFORM_ADMIN"

    @property
    def level(self) -> int:
        hierarchy = {
            AdminRole.VIEWER: 10,
            AdminRole.OPERATOR: 20,
            AdminRole.SECURITY_ADMIN: 30,
            AdminRole.PLATFORM_ADMIN: 40,
        }
        return hierarchy.get(self, 0)

    def can_access(self, required_role: "AdminRole") -> bool:
        """Returns True if this role meets or exceeds the required privilege level."""
        return self.level >= required_role.level


class AuthenticatedIdentity(BaseModel):
    """
    Represents an authenticated human operator or API client interacting with AgentSentinel.
    Explicitly tracks authentication method (API_KEY vs DEV_ANONYMOUS).
    """
    identity_id: str
    name: str
    role: AdminRole
    auth_method: str = "API_KEY"  # "API_KEY" or "DEV_ANONYMOUS"
    key_prefix: Optional[str] = None
    is_authenticated: bool = True
    authenticated_at: datetime = Field(default_factory=utc_now)


class CreateApiKeyRequest(BaseModel):
    """Request payload to issue a new administrative API key."""
    name: str = Field(..., min_length=2, max_length=128, description="Descriptive label for client/operator")
    role: AdminRole = Field(default=AdminRole.VIEWER, description="Administrative authorization role")
    expires_in_days: Optional[int] = Field(default=None, ge=1, le=365, description="Key validity period in days")


class ApiKeyResponse(BaseModel):
    """Public representation of an API key record."""
    key_id: str
    key_prefix: str
    name: str
    role: AdminRole
    is_active: bool
    expires_at: Optional[datetime] = None
    created_at: datetime
    last_used_at: Optional[datetime] = None
    raw_key: Optional[str] = None  # Returned only once upon creation