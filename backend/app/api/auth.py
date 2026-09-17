"""
AgentSentinel Phase 0.9: Administrative Authentication & API Key Management Router.
Allows Platform Administrators to issue and revoke keys with scoped namespaces and idempotency protection.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.crud import list_api_keys, revoke_api_key_record
from app.auth.models import AdminRole, AuthenticatedIdentity, CreateApiKeyRequest, ApiKeyResponse
from app.auth.service import AuthService
from app.auth.dependencies import get_current_identity, require_role
from app.distributed.idempotency import (
    global_idempotency_manager,
    IdempotencyConflictError,
    IdempotencyInProgressError,
    IdempotencyUnavailableError,
)

router = APIRouter(prefix="/api/v1/admin", tags=["Administrative Security & Access Control"])


@router.post(
    "/keys",
    response_model=ApiKeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Issue a new Administrative API Key (Platform Admin only)",
)
def create_api_key(
    payload: CreateApiKeyRequest,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    identity: AuthenticatedIdentity = Depends(require_role(AdminRole.PLATFORM_ADMIN)),
    db: Session = Depends(get_db),
):
    """
    Issues a new API key with the requested role and authorized namespaces.
    Supports Idempotency-Key to prevent duplicate key creation.
    The raw secret key is returned in the response ONCE. It cannot be retrieved later.
    """
    scope = f"admin_keys:{identity.identity_id}"

    if idempotency_key:
        try:
            cached, record = global_idempotency_manager.check_or_start(
                idempotency_key=idempotency_key,
                scope=scope,
                payload=payload.model_dump(),
            )
            if cached and record and record.response_body:
                import json
                cached_dict = json.loads(record.response_body)
                return ApiKeyResponse(**cached_dict)
        except IdempotencyConflictError as ice:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(ice))
        except IdempotencyInProgressError as ipe:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(ipe))
        except IdempotencyUnavailableError as iue:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(iue))

    record, raw_key = AuthService.create_api_key(
        name=payload.name,
        role=payload.role,
        allowed_namespaces=payload.allowed_namespaces,
        expires_in_days=payload.expires_in_days,
        created_by=identity.name,
        db=db,
    )
    if not record:
        if idempotency_key:
            global_idempotency_manager.fail(idempotency_key=idempotency_key, scope=scope)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate administrative API key.",
        )

    response_obj = ApiKeyResponse(
        key_id=record.key_id,
        key_prefix=record.key_prefix,
        name=record.name,
        role=AdminRole(record.role),
        allowed_namespaces=record.allowed_namespaces_json or ["*"],
        is_active=record.is_active,
        expires_at=record.expires_at,
        created_at=record.created_at,
        last_used_at=record.last_used_at,
        raw_key=raw_key,
    )

    if idempotency_key:
        global_idempotency_manager.complete(
            idempotency_key=idempotency_key,
            scope=scope,
            response_code=201,
            response_body=response_obj.model_dump_json(),
        )

    return response_obj


@router.get(
    "/keys",
    response_model=List[ApiKeyResponse],
    summary="List all issued API keys (Security Admin or higher)",
)
def list_keys(
    include_revoked: bool = False,
    identity: AuthenticatedIdentity = Depends(require_role(AdminRole.SECURITY_ADMIN)),
    db: Session = Depends(get_db),
):
    """Lists registered API keys with metadata. Does not reveal secret tokens."""
    records = list_api_keys(db=db, include_revoked=include_revoked)
    return [
        ApiKeyResponse(
            key_id=r.key_id,
            key_prefix=r.key_prefix,
            name=r.name,
            role=AdminRole(r.role),
            allowed_namespaces=r.allowed_namespaces_json or ["*"],
            is_active=r.is_active,
            expires_at=r.expires_at,
            created_at=r.created_at,
            last_used_at=r.last_used_at,
            raw_key=None,
        )
        for r in records
    ]


@router.delete(
    "/keys/{key_id}",
    status_code=status.HTTP_200_OK,
    summary="Revoke an API key (Platform Admin only)",
)
def revoke_key(
    key_id: str,
    identity: AuthenticatedIdentity = Depends(require_role(AdminRole.PLATFORM_ADMIN)),
    db: Session = Depends(get_db),
):
    """Revokes an API key immediately rendering it invalid for all future requests."""
    success = revoke_api_key_record(db=db, key_id=key_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API key '{key_id}' not found or could not be revoked.",
        )
    return {"status": "success", "message": f"API key '{key_id}' revoked successfully."}


@router.get(
    "/identity",
    response_model=AuthenticatedIdentity,
    summary="Inspect current authenticated operator identity",
)
def get_identity(
    identity: AuthenticatedIdentity = Depends(get_current_identity),
):
    """Returns details of the currently authenticated identity and role."""
    return identity