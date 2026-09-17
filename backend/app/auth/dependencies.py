"""
AgentSentinel Phase 0.8: Authentication & Administrative RBAC Dependencies.
FastAPI security dependencies enforcing authentication and administrative authorization.
"""

from typing import Optional
from fastapi import Depends, Header, HTTPException, Security, status
from fastapi.security.api_key import APIKeyHeader
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logger import logger
from app.db.session import get_db
from app.auth.models import AdminRole, AuthenticatedIdentity
from app.auth.service import AuthService

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def get_current_identity(
    x_api_key: Optional[str] = Security(api_key_header),
    authorization: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
) -> AuthenticatedIdentity:
    """
    Centralized authentication dependency.
    Extracts credential from X-API-Key or Authorization: Bearer <key>.
    In production: strictly denies missing or invalid credentials (HTTP 401).
    In development/testing: grants explicitly labeled DEV_ANONYMOUS identity if allowed.
    """
    raw_key = None
    if x_api_key:
        raw_key = x_api_key.strip()
    elif authorization and authorization.startswith("Bearer "):
        raw_key = authorization[7:].strip()

    if raw_key:
        # User provided an API key: strictly validate it
        record = AuthService.verify_api_key(raw_key=raw_key, db=db)
        if not record:
            logger.warning("Authentication failed: invalid, expired, or revoked API key presented.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed: Invalid, expired, or revoked API key.",
                headers={"WWW-Authenticate": "ApiKey"},
            )

        return AuthenticatedIdentity(
            identity_id=record.key_id,
            name=record.name,
            role=AdminRole(record.role),
            auth_method="API_KEY",
            key_prefix=record.key_prefix,
            is_authenticated=True,
        )

    # No credential provided
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