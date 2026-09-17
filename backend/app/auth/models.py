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


from typing import List, Optional

class AuthenticatedIdentity(BaseModel):
    """
    Represents an authenticated human operator, administrative API client, or federated identity.
    Strictly isolated from AI Agent execution identities.
    """
    identity_id: str
    name: str = "Operator"
    role: AdminRole
    auth_method: str = "API_KEY"  # "API_KEY", "OIDC", or "DEV_ANONYMOUS"
    allowed_namespaces: List[str] = Field(default_factory=lambda: ["*"])
    key_prefix: Optional[str] = None
    is_authenticated: bool = True
    is_operator: bool = True
    is_agent: bool = False  # Strict privilege boundary: Human operator cannot execute agent tools directly
    authenticated_at: datetime = Field(default_factory=utc_now)

    def can_access_namespace(self, requested_namespace: str) -> bool:
        """Returns True if this identity is authorized for the requested namespace."""
        if "*" in self.allowed_namespaces:
            return True
        return requested_namespace in self.allowed_namespaces


class CreateApiKeyRequest(BaseModel):
    """Request payload to issue a new administrative API key."""
    name: str = Field(..., min_length=2, max_length=128, description="Descriptive label for client/operator")
    role: AdminRole = Field(default=AdminRole.VIEWER, description="Administrative authorization role")
    allowed_namespaces: List[str] = Field(default_factory=lambda: ["*"], description="Authorized namespaces (['*'] for all)")
    expires_in_days: Optional[int] = Field(default=None, ge=1, le=365, description="Key validity period in days")


class ApiKeyResponse(BaseModel):
    """Public representation of an API key record."""
    key_id: str
    key_prefix: str
    name: str
    role: AdminRole
    allowed_namespaces: List[str] = Field(default_factory=lambda: ["*"])
    is_active: bool
    expires_at: Optional[datetime] = None
    created_at: datetime
    last_used_at: Optional[datetime] = None
    raw_key: Optional[str] = None  # Returned only once upon creation


class OidcTokenPayload(BaseModel):
    """Decoded and validated OIDC claims."""
    sub: str
    iss: str
    aud: str
    exp: int
    email: Optional[str] = None
    name: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    groups: List[str] = Field(default_factory=list)
    namespaces: List[str] = Field(default_factory=list)