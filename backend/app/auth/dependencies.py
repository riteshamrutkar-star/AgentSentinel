"""
AgentSentinel Phase 0.9: Authentication & Administrative RBAC Dependencies.
Enforces:
1. Hybrid Authentication: API Key (X-API-Key) OR Federated OIDC Bearer Token (Authorization: Bearer <jwt>).
2. Administrative RBAC: VIEWER <= OPERATOR <= SECURITY_ADMIN <= PLATFORM_ADMIN.
3. Durable Namespace Authorization: Validates requested namespace against identity's authorized set (default-deny).
4. Strict Identity Isolation: Human operators cannot act as agents, and agent tokens cannot access admin APIs.
"""

from typing import Optional, List, Any
from fastapi import Depends, Header, HTTPException, Security, status
from fastapi.security.api_key import APIKeyHeader
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logger import logger
from app.db.session import get_db
from app.auth.models import AdminRole, AuthenticatedIdentity
from app.auth.service import AuthService
from app.auth.oidc import OidcService, OidcValidationError

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def get_current_identity(
    x_api_key: Optional[str] = Security(api_key_header),
    authorization: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
) -> AuthenticatedIdentity:
    """
    Centralized authentication dependency.
    Accepts:
    - X-API-Key: <key>
    - Authorization: Bearer <key_or_jwt>
    If token appears to be a JWT and OIDC is enabled, validates via OidcService.
    Otherwise validates via AuthService API key registry.
    """
    raw_token = None
    is_bearer = False

    if x_api_key:
        raw_token = x_api_key.strip()
    elif authorization and authorization.startswith("Bearer "):
        raw_token = authorization[7:].strip()
        is_bearer = True

    if raw_token:
        # 1. Check if token is an OIDC JWT (contains '.' and OIDC is enabled or testing)
        if "." in raw_token and (settings.OIDC_ENABLED or settings.TESTING):
            try:
                identity = OidcService.validate_token(raw_token)
                return identity
            except OidcValidationError as ove:
                logger.warning(f"Federated OIDC authentication failed: {ove}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"OIDC authentication failed: {ove}",
                    headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
                )

        # 2. Check as standard AgentSentinel API Key
        record = AuthService.verify_api_key(raw_key=raw_token, db=db)
        if not record:
            logger.warning("Authentication failed: invalid, expired, or revoked API key presented.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed: Invalid, expired, or revoked API key.",
                headers={"WWW-Authenticate": "ApiKey"},
            )

        allowed_namespaces = record.allowed_namespaces_json or ["*"]
        if isinstance(allowed_namespaces, str):
            allowed_namespaces = [allowed_namespaces]

        return AuthenticatedIdentity(
            identity_id=record.key_id,
            name=record.name,
            role=AdminRole(record.role),
            auth_method="API_KEY",
            allowed_namespaces=allowed_namespaces,
            key_prefix=record.key_prefix,
            is_authenticated=True,
            is_operator=True,
            is_agent=False,
        )

    # 3. No credential provided: evaluate dev anonymous fallback
    dev_identity = AuthService.get_dev_anonymous_identity()
    if dev_identity is not None:
        return dev_identity

    # Production mode or anonymous access disabled
    logger.warning("Authentication failed: No credentials provided and anonymous access is disabled.")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required: Please provide an X-API-Key or Authorization Bearer token.",
        headers={"WWW-Authenticate": "ApiKey"},
    )


def require_role(required_role: AdminRole):
    """
    Administrative RBAC dependency factory.
    Enforces minimum role hierarchy level:
    VIEWER (10) <= OPERATOR (20) <= SECURITY_ADMIN (30) <= PLATFORM_ADMIN (40).
    """
    def role_verifier(
        identity: AuthenticatedIdentity = Depends(get_current_identity),
    ) -> AuthenticatedIdentity:
        if not identity.role.can_access(required_role):
            logger.warning(
                f"Administrative RBAC Denied: Identity '{identity.identity_id}' ({identity.role.value}) "
                f"attempted action requiring '{required_role.value}'."
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Administrative access denied: Requires '{required_role.value}' privileges or higher. Current role: '{identity.role.value}'.",
            )
        return identity

    return role_verifier


def require_namespace_access(
    x_namespace: Any = Header(default=None, alias="X-Namespace"),
    identity: Any = Depends(get_current_identity),
) -> str:
    """
    Validates that the authenticated identity is authorized to access the requested namespace.
    Supports both FastAPI dependency injection and direct programmatic invocation.
    Defaults to 'default' namespace if not explicitly requested in header.
    Enforces FAIL-CLOSED / default-deny.
    """
    if isinstance(x_namespace, AuthenticatedIdentity):
        ident = x_namespace
        target_ns = str(identity).strip() if (identity and isinstance(identity, str)) else "default"
    else:
        ident = identity
        target_ns = str(x_namespace).strip() if x_namespace else "default"

    if not ident or not hasattr(ident, "can_access_namespace") or not ident.can_access_namespace(target_ns):
        ident_id = getattr(ident, "identity_id", "unknown") if ident else "unknown"
        allowed = getattr(ident, "allowed_namespaces", []) if ident else []
        logger.warning(
            f"Namespace Access Denied: Identity '{ident_id}' attempted unauthorized access to namespace '{target_ns}'."
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Unauthorized namespace access: Identity '{ident_id}' cannot access '{target_ns}'. Allowed: {allowed}",
        )

    return target_ns


def enforce_operator_isolation(
    identity: AuthenticatedIdentity = Depends(get_current_identity),
    action_type: str = "ADMIN_ACTION",
    caller_is_agent: bool = False,
) -> AuthenticatedIdentity:
    """
    Enforces bidirectional privilege separation:
    - If caller is a human operator token attempting to execute an agent tool call directly -> 403 Forbidden.
    - If caller is an agent identity attempting to access administrative control plane -> 403 Forbidden.
    """
    if caller_is_agent and getattr(identity, "is_operator", False) and not getattr(identity, "is_agent", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Human operator identity cannot directly execute agent actions without delegation proxy.",
        )

    if getattr(identity, "is_agent", False) and not getattr(identity, "is_operator", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Agent identity cannot perform human operator actions on administrative control plane.",
        )

    return identity


def require_operator_identity(
    identity: AuthenticatedIdentity = Depends(get_current_identity),
) -> AuthenticatedIdentity:
    """Enforces that the authenticated identity is an operator/administrative principal."""
    if getattr(identity, "is_agent", False) and not getattr(identity, "is_operator", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Agent identity cannot perform human operator actions on administrative control plane.",
        )
    return identity