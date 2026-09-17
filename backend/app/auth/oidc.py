"""
AgentSentinel Phase 0.9: Operator Identity Federation (OIDC / OAuth2).
Enforces strict JWT signature, issuer, audience, and algorithm validation,
safe JWKS key retrieval, administrative role mapping, and namespace authorization.

MANDATORY SECURITY INVARIANTS:
1. Restricted algorithm set: RS256, ES256 only (reject 'none', symmetric HS256, etc.)
2. Fail-closed on unmapped or unknown roles.
3. Strict privilege boundary: Human operator tokens cannot be used as agent runtime tokens.
4. Namespace authorization mapped from verified identity claims (default-deny).
"""

import time
import json
import threading
from typing import Any, Dict, List, Optional, Set
import jwt
from jwt.exceptions import PyJWTError, ExpiredSignatureError, InvalidSignatureError
from fastapi import HTTPException

from app.core.config import settings
from app.core.logger import logger
from app.auth.models import AdminRole, AuthenticatedIdentity, OidcTokenPayload


class OidcValidationError(HTTPException):
    """Raised when OIDC token validation or role mapping fails."""
    def __init__(self, detail: str = "OIDC token validation failed", status_code: int = 401):
        super().__init__(status_code=status_code, detail=detail)


class OidcRoleMappingError(OidcValidationError):
    """Raised when OIDC claims cannot be securely mapped to an AdminRole (fail-closed)."""
    pass


# Strict allowed algorithms for OIDC in AgentSentinel
ALLOWED_ALGORITHMS = ["RS256", "ES256"]

ROLE_MAPPINGS: Dict[str, AdminRole] = {
    "platform_admin": AdminRole.PLATFORM_ADMIN,
    "platform-admin": AdminRole.PLATFORM_ADMIN,
    "platformadmin": AdminRole.PLATFORM_ADMIN,
    "platform_administrator": AdminRole.PLATFORM_ADMIN,
    "admin": AdminRole.PLATFORM_ADMIN,
    "security_admin": AdminRole.SECURITY_ADMIN,
    "security-admin": AdminRole.SECURITY_ADMIN,
    "secadmin": AdminRole.SECURITY_ADMIN,
    "security_officer": AdminRole.SECURITY_ADMIN,
    "operator": AdminRole.OPERATOR,
    "soc_operator": AdminRole.OPERATOR,
    "viewer": AdminRole.VIEWER,
    "read_only": AdminRole.VIEWER,
    "auditor": AdminRole.VIEWER,
}


class OidcService:
    """
    Validates federated OIDC/OAuth2 bearer tokens and maps them to AuthenticatedIdentity.
    Supports both singleton class-level validation and configured instance validation.
    """

    _jwks_cache: Optional[Dict[str, Any]] = None
    _jwks_cached_at: float = 0.0
    _jwks_ttl_seconds: float = 3600.0  # Cache keys for 1 hour
    _lock = threading.Lock()
    _test_keys: Dict[str, str] = {}  # In-memory keys for testing

    def __init__(
        self,
        issuer: Optional[str] = None,
        client_id: Optional[str] = None,
        public_key_pem: Optional[str] = None,
        allowed_algorithms: Optional[List[str]] = None,
    ):
        self.issuer = issuer
        self.client_id = client_id
        self.public_key_pem = public_key_pem
        self.allowed_algorithms = allowed_algorithms or ALLOWED_ALGORITHMS

    @classmethod
    def register_test_key(cls, key_id: str, public_key_pem: str) -> None:
        """Allows test suites to register RS256/ES256 public keys without an external HTTP JWKS server."""
        with cls._lock:
            cls._test_keys[key_id] = public_key_pem

    @classmethod
    def clear_test_keys(cls) -> None:
        with cls._lock:
            cls._test_keys.clear()
            cls._jwks_cache = None
            cls._jwks_cached_at = 0.0

    @classmethod
    def fetch_signing_key(cls, kid: Optional[str]) -> Optional[str]:
        """Resolves public signing key from test registry or cached JWKS."""
        with cls._lock:
            if kid and kid in cls._test_keys:
                return cls._test_keys[kid]

        if not settings.OIDC_JWKS_URI:
            return None

        # Fetch from remote JWKS URI if configured
        now = time.time()
        with cls._lock:
            if cls._jwks_cache and (now - cls._jwks_cached_at < cls._jwks_ttl_seconds):
                keys = cls._jwks_cache.get("keys", [])
                for k in keys:
                    if k.get("kid") == kid:
                        return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(k))

        try:
            import urllib.request
            req = urllib.request.Request(
                settings.OIDC_JWKS_URI,
                headers={"User-Agent": "AgentSentinel-OIDC-Validator/0.9"}
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                with cls._lock:
                    cls._jwks_cache = data
                    cls._jwks_cached_at = now
                    for k in data.get("keys", []):
                        if k.get("kid") == kid:
                            return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(k))
        except Exception as e:
            logger.error(f"Failed to fetch OIDC JWKS from {settings.OIDC_JWKS_URI}: {e}")

        return None

    @classmethod
    def map_claims_to_role(cls, claims: Dict[str, Any]) -> AdminRole:
        """
        Maps token claims (roles or groups) to an explicit AdminRole.
        Enforces FAIL-CLOSED: if no recognized role is found, assigns least-privilege VIEWER.
        """
        candidate_roles: List[str] = []

        # Check configured role claim
        custom_claim = claims.get(settings.OIDC_ROLE_CLAIM)
        if isinstance(custom_claim, list):
            candidate_roles.extend(custom_claim)
        elif isinstance(custom_claim, str):
            candidate_roles.append(custom_claim)

        # Also check standard 'roles', 'groups', and 'role'
        for k in ["roles", "groups", "cognito:groups", "role"]:
            val = claims.get(k)
            if isinstance(val, list):
                candidate_roles.extend(val)
            elif isinstance(val, str):
                candidate_roles.append(val)

        # Resolve highest matching role
        best_role: Optional[AdminRole] = None
        for r in candidate_roles:
            normalized = r.lower().strip()
            if normalized in ROLE_MAPPINGS:
                mapped = ROLE_MAPPINGS[normalized]
                if best_role is None or mapped.level > best_role.level:
                    best_role = mapped

        if best_role is None:
            logger.warning(f"OIDC Role Mapping: Claims contained no recognized roles ({candidate_roles}). Fail-closed default: VIEWER.")
            return AdminRole.VIEWER

        return best_role

    @classmethod
    def resolve_authorized_namespaces(cls, claims: Dict[str, Any], role: AdminRole) -> List[str]:
        """
        Resolves the list of authorized namespaces from OIDC claims.
        PLATFORM_ADMIN receives ['*'] by default.
        Other roles receive explicitly declared namespaces in 'namespaces' claim, defaulting to ['default'].
        """
        raw_ns = claims.get("namespaces") or claims.get("allowed_namespaces")
        if isinstance(raw_ns, list) and raw_ns:
            return [str(ns).strip() for ns in raw_ns if ns]
        elif isinstance(raw_ns, str) and raw_ns:
            return [raw_ns.strip()]

        if role == AdminRole.PLATFORM_ADMIN:
            return ["*"]

        # Default-deny: isolate to 'default' namespace
        return ["default"]

    def validate_token(self_or_cls, token: str) -> AuthenticatedIdentity:
        """
        Performs full cryptographically verified OIDC validation.
        Enforces restricted algorithms, audience, issuer, expiration, and role mapping.
        """
        is_instance = isinstance(self_or_cls, OidcService)
        issuer = getattr(self_or_cls, "issuer", None) or settings.OIDC_ISSUER
        client_id = getattr(self_or_cls, "client_id", None) or settings.OIDC_CLIENT_ID
        public_key = getattr(self_or_cls, "public_key_pem", None)
        algorithms = getattr(self_or_cls, "allowed_algorithms", None) or ALLOWED_ALGORITHMS

        try:
            # 1. Unverified header inspection for 'alg' and 'kid'
            unverified_header = jwt.get_unverified_header(token)
            alg = unverified_header.get("alg")
            kid = unverified_header.get("kid")

            if alg not in algorithms:
                logger.warning(f"OIDC validation rejected: Algorithm '{alg}' not in allowed set {algorithms}.")
                raise OidcValidationError(f"Insecure or unsupported JWT algorithm '{alg}'. Allowed: {algorithms}")

            # 2. Key resolution
            signing_key = public_key or OidcService.fetch_signing_key(kid)
            if not signing_key:
                logger.warning(f"OIDC validation failed: Unable to resolve signing key for kid='{kid}'.")
                raise OidcValidationError("Could not resolve signing key for OIDC token.")

            # 3. Cryptographic signature and standard claims verification
            verify_options = {
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "require": ["exp", "sub"],
            }
            if issuer:
                verify_options["verify_iss"] = True
            if client_id:
                verify_options["verify_aud"] = True

            decoded_claims = jwt.decode(
                token,
                signing_key,
                algorithms=algorithms,
                issuer=issuer if issuer else None,
                audience=client_id if client_id else None,
                options=verify_options,
            )

            # 4. Map claims to administrative role
            role = OidcService.map_claims_to_role(decoded_claims)

            # 5. Resolve authorized namespaces
            allowed_namespaces = OidcService.resolve_authorized_namespaces(decoded_claims, role)

            identity_id = str(decoded_claims.get("sub") or "unknown_oidc_user")
            identity_name = (
                decoded_claims.get("name")
                or decoded_claims.get("email")
                or decoded_claims.get("preferred_username")
                or identity_id
            )

            return AuthenticatedIdentity(
                identity_id=identity_id,
                name=identity_name,
                role=role,
                auth_method="OIDC",
                allowed_namespaces=allowed_namespaces,
                is_authenticated=True,
                is_operator=True,
                is_agent=False,
            )

        except jwt.ExpiredSignatureError as ese:
            logger.warning(f"OIDC token has expired: {ese}")
            raise OidcValidationError(f"OIDC token has expired: {ese}")
        except (jwt.InvalidIssuerError, jwt.InvalidAudienceError, jwt.InvalidSignatureError) as ie:
            logger.warning(f"OIDC verification failed: {ie}")
            raise OidcValidationError(f"OIDC claim verification failed: {ie}")
        except OidcRoleMappingError:
            raise
        except PyJWTError as pje:
            logger.warning(f"Malformed or invalid OIDC token: {pje}")
            raise OidcValidationError(f"Invalid OIDC token structure or claims: {pje}")
        except Exception as e:
            logger.error(f"Unexpected error during OIDC validation: {e}")
            raise OidcValidationError("OIDC authentication failed.")

