"""
Unit and integration tests for AgentSentinel Phase 0.9: Operator Identity Federation (OIDC)
and Strict Privilege Separation.
"""

import time
import pytest
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from fastapi import HTTPException
from unittest.mock import patch

from app.auth.models import AdminRole, AuthenticatedIdentity
from app.auth.oidc import OidcService
from app.auth.dependencies import enforce_operator_isolation, require_namespace_access


@pytest.fixture(scope="module")
def rsa_keypair():
    """Generates an ephemeral RSA 2048-bit keypair for test RS256 token signing."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return {"private_pem": private_pem, "public_pem": public_pem}


def make_jwt(payload: dict, private_pem: str, algorithm: str = "RS256") -> str:
    return jwt.encode(payload, private_pem, algorithm=algorithm)


# --- 1. OIDC Token Validation Tests ---

def test_oidc_valid_rs256_token(rsa_keypair):
    service = OidcService(
        issuer="https://auth.example.com",
        client_id="agentsentinel-soc",
        public_key_pem=rsa_keypair["public_pem"],
        allowed_algorithms=["RS256"],
    )

    now = int(time.time())
    claims = {
        "iss": "https://auth.example.com",
        "aud": "agentsentinel-soc",
        "sub": "user_admin_001",
        "email": "soc_lead@example.com",
        "exp": now + 3600,
        "iat": now,
        "role": "platform_admin",
        "namespaces": ["default", "production-finance"],
    }
    token = make_jwt(claims, rsa_keypair["private_pem"])

    identity = service.validate_token(token)
    assert identity.identity_id == "user_admin_001"
    assert identity.role == AdminRole.PLATFORM_ADMIN
    assert identity.is_operator is True
    assert identity.is_agent is False
    assert identity.allowed_namespaces == ["default", "production-finance"]
    assert identity.can_access_namespace("production-finance") is True
    assert identity.can_access_namespace("secret-vault") is False


def test_oidc_expired_token_rejected(rsa_keypair):
    service = OidcService(
        issuer="https://auth.example.com",
        client_id="agentsentinel-soc",
        public_key_pem=rsa_keypair["public_pem"],
    )

    now = int(time.time())
    claims = {
        "iss": "https://auth.example.com",
        "aud": "agentsentinel-soc",
        "sub": "user_expired",
        "exp": now - 60,  # Expired 1 minute ago
        "iat": now - 3600,
        "role": "operator",
    }
    token = make_jwt(claims, rsa_keypair["private_pem"])

    with pytest.raises(HTTPException) as exc_info:
        service.validate_token(token)
    assert exc_info.value.status_code == 401
    assert "expired" in exc_info.value.detail.lower()


def test_oidc_invalid_issuer_rejected(rsa_keypair):
    service = OidcService(
        issuer="https://auth.example.com",
        client_id="agentsentinel-soc",
        public_key_pem=rsa_keypair["public_pem"],
    )

    now = int(time.time())
    claims = {
        "iss": "https://malicious-issuer.com",
        "aud": "agentsentinel-soc",
        "sub": "user_bad_iss",
        "exp": now + 3600,
        "iat": now,
        "role": "operator",
    }
    token = make_jwt(claims, rsa_keypair["private_pem"])

    with pytest.raises(HTTPException) as exc_info:
        service.validate_token(token)
    assert exc_info.value.status_code == 401
    assert "issuer" in exc_info.value.detail.lower()


def test_oidc_invalid_audience_rejected(rsa_keypair):
    service = OidcService(
        issuer="https://auth.example.com",
        client_id="agentsentinel-soc",
        public_key_pem=rsa_keypair["public_pem"],
    )

    now = int(time.time())
    claims = {
        "iss": "https://auth.example.com",
        "aud": "unauthorized-application",
        "sub": "user_bad_aud",
        "exp": now + 3600,
        "iat": now,
        "role": "operator",
    }
    token = make_jwt(claims, rsa_keypair["private_pem"])

    with pytest.raises(HTTPException) as exc_info:
        service.validate_token(token)
    assert exc_info.value.status_code == 401
    assert "audience" in exc_info.value.detail.lower()


def test_oidc_unknown_role_fail_closed(rsa_keypair):
    """Unknown or unmapped roles must fail closed (assigned VIEWER or rejected)."""
    service = OidcService(
        issuer="https://auth.example.com",
        client_id="agentsentinel-soc",
        public_key_pem=rsa_keypair["public_pem"],
    )

    now = int(time.time())
    claims = {
        "iss": "https://auth.example.com",
        "aud": "agentsentinel-soc",
        "sub": "user_unknown_role",
        "exp": now + 3600,
        "iat": now,
        "role": "some_random_untrusted_group",
    }
    token = make_jwt(claims, rsa_keypair["private_pem"])

    identity = service.validate_token(token)
    # Fail-closed assignment to least privilege (VIEWER)
    assert identity.role == AdminRole.VIEWER


# --- 2. Privilege Boundary Isolation Tests ---

def test_operator_privilege_isolation_rejection():
    """Human operator token cannot masquerade as an autonomous agent directly."""
    operator_identity = AuthenticatedIdentity(
        identity_id="human_soc_operator",
        role=AdminRole.OPERATOR,
        is_operator=True,
        is_agent=False,
    )

    # Calling enforce_operator_isolation with caller_is_agent=True must reject operator
    with pytest.raises(HTTPException) as exc_info:
        enforce_operator_isolation(
            identity=operator_identity,
            action_type="AGENT_TOOL_CALL",
            caller_is_agent=True,
        )
    assert exc_info.value.status_code == 403
    assert "Human operator identity cannot directly execute agent actions" in exc_info.value.detail


def test_agent_privilege_isolation_rejection():
    """Autonomous agent identity cannot access administrative control plane."""
    agent_identity = AuthenticatedIdentity(
        identity_id="agent_crawler_01",
        role=AdminRole.VIEWER,
        is_operator=False,
        is_agent=True,
    )

    with pytest.raises(HTTPException) as exc_info:
        enforce_operator_isolation(
            identity=agent_identity,
            action_type="ADMIN_MUTATION",
            caller_is_agent=False,
        )
    assert exc_info.value.status_code == 403
    assert "Agent identity cannot perform human operator actions" in exc_info.value.detail


# --- 3. Namespace Authorization Tests ---

def test_namespace_access_enforcement():
    scoped_identity = AuthenticatedIdentity(
        identity_id="operator_team_b",
        role=AdminRole.OPERATOR,
        allowed_namespaces=["team-b", "shared-staging"],
    )

    # Allowed namespace passes
    require_namespace_access(scoped_identity, "team-b")
    require_namespace_access(scoped_identity, "shared-staging")

    # Unauthorized namespace raises 403
    with pytest.raises(HTTPException) as exc_info:
        require_namespace_access(scoped_identity, "team-a-confidential")
    assert exc_info.value.status_code == 403
    assert "Unauthorized namespace access" in exc_info.value.detail
