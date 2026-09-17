"""
AgentSentinel Phase 0.8: Authentication Service.
Handles cryptographic key generation, HMAC-SHA-256 hashing, verification,
revocation, and centralized dev/test anonymous identity provision.
"""

import hmac
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, List
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logger import logger
from app.auth.models import AdminRole, AuthenticatedIdentity
from app.db.models import ApiKeyModel
from app.db.crud import (
    create_api_key_record,
    get_api_key_by_hash,
    list_api_keys,
    revoke_api_key_record,
    touch_api_key_last_used,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AuthService:
    """Centralized service managing API credential hashing, issuance, and verification."""

    @classmethod
    def hash_key(cls, raw_key: str) -> str:
        """Computes HMAC-SHA-256 digest of raw key using system API secret."""
        salt = settings.API_SECRET_KEY.encode("utf-8")
        return hmac.new(salt, raw_key.encode("utf-8"), hashlib.sha256).hexdigest()

    @classmethod
    def create_api_key(
        cls,
        name: str,
        role: AdminRole = AdminRole.VIEWER,
        expires_in_days: Optional[int] = None,
        created_by: str = "system",
        db: Optional[Session] = None,
    ) -> Tuple[Optional[ApiKeyModel], str]:
        """
        Generates a new administrative API key.
        Returns the persistent record and the raw key string (returned once only).
        """
        prefix_tag = "test" if settings.ENVIRONMENT == "testing" else "live"
        random_part = secrets.token_hex(20)
        raw_key = f"as_{prefix_tag}_{random_part}"
        key_prefix = raw_key[:12]
        key_hash = cls.hash_key(raw_key)
        key_id = f"key_{uuid.uuid4().hex[:10]}"

        expires_at = None
        if expires_in_days is not None:
            expires_at = utc_now() + timedelta(days=expires_in_days)

        record = create_api_key_record(
            db=db,
            key_id=key_id,
            key_prefix=key_prefix,
            key_hash=key_hash,
            name=name,
            role=role.value,
            expires_at=expires_at,
            created_by=created_by,
        )

        logger.info(f"AuthService: Generated new API key '{key_prefix}...' for role '{role.value}' (Name: {name})")
        return record, raw_key

    @classmethod
    def verify_api_key(cls, raw_key: str, db: Optional[Session] = None) -> Optional[ApiKeyModel]:
        """
        Cryptographically validates an API key against database records.
        Checks existence, active status, and expiration.
        Updates last_used_at on valid match.
        """
        if not raw_key or not raw_key.startswith("as_"):
            return None

        key_hash = cls.hash_key(raw_key)
        record = get_api_key_by_hash(db, key_hash)
        if not record:
            return None

        if not record.is_active:
            logger.warning(f"AuthService: Attempted use of revoked key prefix '{record.key_prefix}'")
            return None

        if record.expires_at is not None:
            # Normalize to UTC comparison
            exp = record.expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if utc_now() > exp:
                logger.warning(f"AuthService: Attempted use of expired key prefix '{record.key_prefix}'")
                return None

        touch_api_key_last_used(db, record.key_id)
        return record

    @classmethod
    def get_dev_anonymous_identity(cls) -> Optional[AuthenticatedIdentity]:
        """
        Provides a clearly labeled local development/testing identity when explicitly allowed.
        Strictly disallowed in production environments.
        """
        if settings.ENVIRONMENT.lower() == "production":
            return None

        if not settings.ALLOW_DEV_ANONYMOUS:
            return None

        return AuthenticatedIdentity(
            identity_id="id_dev_local",
            name="Development Local Operator",
            role=AdminRole.PLATFORM_ADMIN,
            auth_method="DEV_ANONYMOUS",
            key_prefix="dev_anon",
            is_authenticated=True,
        )

    @classmethod
    def create_key(
        cls,
        db_or_name,
        name_or_role=None,
        role: AdminRole = AdminRole.VIEWER,
        expires_in_days: Optional[int] = None,
        created_by: str = "system",
        db: Optional[Session] = None,
        name: Optional[str] = None,
    ) -> Tuple[Optional[ApiKeyModel], str]:
        if isinstance(db_or_name, Session):
            target_db = db_or_name
            target_name = name or name_or_role or "Unnamed Key"
        else:
            target_db = db
            target_name = name or str(db_or_name)
            if isinstance(name_or_role, AdminRole):
                role = name_or_role
        return cls.create_api_key(
            name=target_name,
            role=role,
            expires_in_days=expires_in_days,
            created_by=created_by,
            db=target_db,
        )

    @classmethod
    def verify_key(cls, db_or_key, raw_key_or_none: Optional[str] = None) -> Optional[ApiKeyModel]:
        if isinstance(db_or_key, Session):
            return cls.verify_api_key(raw_key=raw_key_or_none or "", db=db_or_key)
        return cls.verify_api_key(raw_key=str(db_or_key), db=None)

    @classmethod
    def revoke_key(cls, db: Session, key_id: str) -> bool:
        return revoke_api_key_record(db, key_id)

    @classmethod
    def _hash_key(cls, raw_key: str) -> str:
        return cls.hash_key(raw_key)


auth_service = AuthService()
ApiKeyService = AuthService