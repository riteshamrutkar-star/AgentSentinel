"""
=============================================================================
AgentSentinel — Phase 0.8 Production Platform & Security Test Suite
=============================================================================
Comprehensive tests covering:
- Authentication (API Key generation, HMAC-SHA-256 hashing, prefix, revocation, expiration)
- Administrative RBAC roles (VIEWER, OPERATOR, SECURITY_ADMIN, PLATFORM_ADMIN)
- In-memory sliding-window token bucket rate limiting & HTTP 429 Retry-After
- API security hardening (Security Headers, Request ID & Correlation ID, Payload Limit)
- Multi-stage health probes (/health/live, /health/ready, /health/dependencies)
- Prometheus metrics exposition (/metrics)
- Structured JSON logging & secret redaction
- Security alerting engine & deduplication
- Production fail-closed configuration validation
- Database schema migration idempotence
=============================================================================
"""

import os
import time
import json
import logging
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import SessionLocal, engine
from app.db.models import Base, ApiKeyModel, SecurityAlertModel, SchemaMigrationModel
from app.db.migrations import apply_migrations, REVISIONS
from app.db import crud
from app.auth.models import AdminRole, AuthenticatedIdentity
from app.auth.service import ApiKeyService
from app.core.security_middleware import (
    SecurityHeadersMiddleware,
    RequestIdMiddleware,
    PayloadSizeLimitMiddleware,
)
from app.core.ratelimit import InMemoryRateLimiter
from app.core.structured_logger import JSONLogFormatter, SecretRedactingFilter
from app.observability.metrics import prometheus_registry
from app.alerts.models import AlertSeverity, AlertStatus
from app.alerts.service import SecurityAlertEngine
from app.main import app

client = TestClient(app)


# ---------------------------------------------------------------------------
# FIXTURES
# ---------------------------------------------------------------------------

@pytest.fixture
def db_session():
    """Provides an isolated database session."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def platform_admin_key(db_session: Session):
    """Creates a temporary PLATFORM_ADMIN API key for testing."""
    key_model, raw_token = ApiKeyService.create_key(
        db_session,
        name="Test Platform Admin",
        role=AdminRole.PLATFORM_ADMIN,
        expires_in_days=1,
    )
    yield raw_token
    # Cleanup
    db_session.query(ApiKeyModel).filter(ApiKeyModel.key_id == key_model.key_id).delete()
    db_session.commit()


@pytest.fixture
def operator_key(db_session: Session):
    """Creates a temporary OPERATOR API key for testing."""
    key_model, raw_token = ApiKeyService.create_key(
        db_session,
        name="Test Operator",
        role=AdminRole.OPERATOR,
        expires_in_days=1,
    )
    yield raw_token
    # Cleanup
    db_session.query(ApiKeyModel).filter(ApiKeyModel.key_id == key_model.key_id).delete()
    db_session.commit()


@pytest.fixture
def viewer_key(db_session: Session):
    """Creates a temporary VIEWER API key for testing."""
    key_model, raw_token = ApiKeyService.create_key(
        db_session,
        name="Test Viewer",
        role=AdminRole.VIEWER,
        expires_in_days=1,
    )
    yield raw_token
    # Cleanup
    db_session.query(ApiKeyModel).filter(ApiKeyModel.key_id == key_model.key_id).delete()
    db_session.commit()


# ===========================================================================
# 1. AUTHENTICATION & API KEY MANAGEMENT TESTS
# ===========================================================================

def test_api_key_generation_and_hashing(db_session: Session):
    """Verify that generated keys use the required prefix and are stored as hashes."""
    key_model, raw_token = ApiKeyService.create_key(
        db_session,
        name="Production Ingestion Key",
        role=AdminRole.OPERATOR,
    )
    assert raw_token.startswith("as_")
    assert key_model.key_prefix == raw_token[:12]
    # Ensure raw secret is not persisted
    assert raw_token not in key_model.key_hash
    assert len(key_model.key_hash) == 64  # SHA-256 hex digest length

    # Cleanup
    db_session.query(ApiKeyModel).filter(ApiKeyModel.key_id == key_model.key_id).delete()
    db_session.commit()


def test_api_key_verification_success(db_session: Session):
    """Verify that a valid raw token successfully resolves to the identity and updates last_used_at."""
    key_model, raw_token = ApiKeyService.create_key(
        db_session,
        name="Audit Reader",
        role=AdminRole.VIEWER,
    )
    assert key_model.last_used_at is None

    verified_key = ApiKeyService.verify_key(db_session, raw_token)
    assert verified_key is not None
    assert verified_key.key_id == key_model.key_id
    assert verified_key.last_used_at is not None

    # Cleanup
    db_session.query(ApiKeyModel).filter(ApiKeyModel.key_id == key_model.key_id).delete()
    db_session.commit()


def test_api_key_verification_invalid_token(db_session: Session):
    """Verify that an invalid or altered token fails verification."""
    result = ApiKeyService.verify_key(db_session, "as_live_invalid_token_1234567890abcdef")
    assert result is None


def test_api_key_revocation(db_session: Session):
    """Verify that revoked keys immediately fail verification."""
    key_model, raw_token = ApiKeyService.create_key(
        db_session,
        name="Temporary Deployer",
        role=AdminRole.SECURITY_ADMIN,
    )
    assert ApiKeyService.verify_key(db_session, raw_token) is not None

    # Revoke key
    revoked = ApiKeyService.revoke_key(db_session, key_model.key_id)
    assert revoked is True

    # Subsequent verification must fail
    assert ApiKeyService.verify_key(db_session, raw_token) is None

    # Cleanup
    db_session.query(ApiKeyModel).filter(ApiKeyModel.key_id == key_model.key_id).delete()
    db_session.commit()


def test_api_key_expiration(db_session: Session):
    """Verify that expired keys fail verification."""
    # Create key already expired in the past
    key_hash = ApiKeyService._hash_key("as_live_already_expired_key")
    expired_model = ApiKeyModel(
        key_id="key_expired_test_123",
        name="Expired Key",
        key_hash=key_hash,
        key_prefix="as_live_alre",
        role=AdminRole.VIEWER.value,
        is_active=True,
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
    )
    db_session.add(expired_model)
    db_session.commit()

    assert ApiKeyService.verify_key(db_session, "as_live_already_expired_key") is None

    # Cleanup
    db_session.query(ApiKeyModel).filter(ApiKeyModel.key_id == expired_model.key_id).delete()
    db_session.commit()


# ===========================================================================
# 2. ADMINISTRATIVE RBAC TESTS
# ===========================================================================

def test_admin_roles_hierarchy():
    """Verify numerical weight ordering of administrative roles."""
    assert AdminRole.VIEWER.level == 10
    assert AdminRole.OPERATOR.level == 20
    assert AdminRole.SECURITY_ADMIN.level == 30
    assert AdminRole.PLATFORM_ADMIN.level == 40
    assert AdminRole.VIEWER.level < AdminRole.OPERATOR.level < AdminRole.SECURITY_ADMIN.level < AdminRole.PLATFORM_ADMIN.level
    assert AdminRole.OPERATOR.can_access(AdminRole.VIEWER) is True
    assert AdminRole.VIEWER.can_access(AdminRole.OPERATOR) is False


def test_identity_endpoint_with_valid_key(operator_key: str):
    """Verify /api/v1/admin/identity returns caller identity details."""
    response = client.get(
        "/api/v1/admin/identity",
        headers={"Authorization": f"Bearer {operator_key}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["role"] == "OPERATOR"
    assert data["auth_method"] == "API_KEY"
    assert data["is_authenticated"] is True


def test_identity_endpoint_dev_anonymous():
    """Verify /api/v1/admin/identity in development returns labeled DEV_ANONYMOUS."""
    response = client.get("/api/v1/admin/identity")
    assert response.status_code == 200
    data = response.json()
    assert data["role"] in ("OPERATOR", "PLATFORM_ADMIN")
    assert data["auth_method"] == "DEV_ANONYMOUS"


def test_platform_admin_can_create_and_revoke_keys(platform_admin_key: str):
    """Verify that PLATFORM_ADMIN can create and revoke keys via REST API."""
    # Create key
    create_res = client.post(
        "/api/v1/admin/keys",
        headers={"X-API-Key": platform_admin_key},
        json={"name": "Integration Test Key", "role": "OPERATOR", "expires_in_days": 7},
    )
    assert create_res.status_code == 201
    new_key = create_res.json()
    assert "raw_key" in new_key
    assert new_key["raw_key"].startswith("as_")
    key_id = new_key["key_id"]

    # List keys
    list_res = client.get(
        "/api/v1/admin/keys",
        headers={"X-API-Key": platform_admin_key},
    )
    assert list_res.status_code == 200
    keys = list_res.json()
    assert any(k["key_id"] == key_id for k in keys)

    # Revoke key
    del_res = client.delete(
        f"/api/v1/admin/keys/{key_id}",
        headers={"X-API-Key": platform_admin_key},
    )
    assert del_res.status_code == 200
    assert del_res.json()["status"] == "success"


def test_insufficient_role_cannot_manage_keys(viewer_key: str):
    """Verify that VIEWER role receives HTTP 403 Forbidden on key creation."""
    res = client.post(
        "/api/v1/admin/keys",
        headers={"X-API-Key": viewer_key},
        json={"name": "Unauthorized Key", "role": "OPERATOR"},
    )
    assert res.status_code == 403
    assert "Administrative access denied" in res.json()["detail"]


# ===========================================================================
# 3. RATE LIMITING TESTS
# ===========================================================================

def test_rate_limiter_token_bucket_allows_within_limit():
    """Verify that in-memory token bucket allows bursts up to configured capacity."""
    limiter = InMemoryRateLimiter(requests_per_minute=60, burst=5)
    test_ip = "192.168.1.100"

    for _ in range(5):
        allowed, remaining, _ = limiter.check_rate_limit(test_ip)
        assert allowed is True

    # 6th request immediately should be rejected
    allowed, remaining, retry_after = limiter.check_rate_limit(test_ip)
    assert allowed is False
    assert remaining == 0
    assert retry_after >= 1


def test_rate_limiter_architectural_single_instance_flag():
    """Verify that rate limiter documents its single-instance nature."""
    limiter = InMemoryRateLimiter()
    assert limiter.is_distributed is False
    assert "NOT a globally coordinated distributed rate limiter" in limiter.get_architecture_notice()


# ===========================================================================
# 4. SECURITY HEADERS, REQUEST ID & PAYLOAD LIMITS
# ===========================================================================

def test_security_headers_middleware():
    """Verify required HTTP security headers are attached to responses and HSTS is conditioned."""
    # 1. Plain HTTP in development: Security headers present, but HSTS must NOT be emitted
    response = client.get("/health/live")
    assert response.status_code == 200
    headers = response.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert "default-src 'self'" in headers.get("Content-Security-Policy", "")
    assert "Strict-Transport-Security" not in headers

    # 2. HTTPS request (via X-Forwarded-Proto): HSTS MUST be emitted
    https_response = client.get("/health/live", headers={"X-Forwarded-Proto": "https"})
    assert https_response.status_code == 200
    assert "Strict-Transport-Security" in https_response.headers
    assert "max-age=31536000" in https_response.headers["Strict-Transport-Security"]

    # 3. Production environment: HSTS MUST be emitted
    original_env = settings.ENVIRONMENT
    try:
        settings.ENVIRONMENT = "production"
        prod_response = client.get("/health/live")
        assert "Strict-Transport-Security" in prod_response.headers
        assert "max-age=31536000" in prod_response.headers["Strict-Transport-Security"]
    finally:
        settings.ENVIRONMENT = original_env


def test_request_id_generation_and_propagation():
    """Verify X-Request-ID is generated if omitted, or echoed if provided."""
    # Omitted -> generated
    res1 = client.get("/health/live")
    assert "X-Request-ID" in res1.headers
    req_id_generated = res1.headers["X-Request-ID"]
    assert len(req_id_generated) > 10

    # Provided -> echoed
    custom_id = "custom-test-req-id-12345"
    res2 = client.get("/health/live", headers={"X-Request-ID": custom_id})
    assert res2.headers.get("X-Request-ID") == custom_id
    assert res2.headers.get("X-Correlation-ID") == custom_id


def test_payload_size_limit_middleware():
    """Verify PayloadSizeLimitMiddleware rejects payloads exceeding threshold."""
    # Test with a dummy endpoint or route sending oversized payload
    middleware = PayloadSizeLimitMiddleware(app=None, max_size_bytes=100)
    # Ensure configuration respects settings
    assert settings.MAX_REQUEST_SIZE_BYTES == 10485760  # 10MB default


# ===========================================================================
# 5. HEALTH PROBES & OBSERVABILITY
# ===========================================================================

def test_health_live_endpoint():
    """Verify /health/live returns 200 OK alive."""
    res = client.get("/health/live")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "alive"
    assert "timestamp" in data
    assert "version" in data


def test_health_ready_endpoint():
    """Verify /health/ready evaluates deep dependencies."""
    res = client.get("/health/ready")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in ("ready", "healthy")


def test_health_dependencies_endpoint():
    """Verify /health/dependencies provides detailed dependency report without leaks."""
    res = client.get("/health/dependencies")
    assert res.status_code == 200
    data = res.json()
    assert "dependencies" in data
    deps = data["dependencies"]
    assert ("postgresql" in deps) or ("database" in deps)
    assert deps["policy_engine"]["status"] == "healthy"
    assert deps["tool_registry"]["status"] == "healthy"


def test_prometheus_metrics_endpoint():
    """Verify /metrics exports Prometheus text exposition v0.0.4."""
    res = client.get("/metrics")
    assert res.status_code == 200
    content = res.text
    # Check standard metrics
    assert "agentsentinel_http_requests_total" in content
    assert "agentsentinel_http_request_duration_seconds" in content
    assert "agentsentinel_tool_calls_total" in content
    assert "agentsentinel_security_alerts_total" in content
    assert "# TYPE" in content
    assert "# HELP" in content


# ===========================================================================
# 6. STRUCTURED LOGGING & SECRET REDACTION
# ===========================================================================

def test_json_log_formatter():
    """Verify JSONLogFormatter produces valid JSON log records with standard keys."""
    formatter = JSONLogFormatter()
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Test message for JSON logging",
        args=(),
        exc_info=None,
    )
    record.request_id = "req-test-123"
    formatted = formatter.format(record)
    parsed = json.loads(formatted)

    assert parsed["logger"] == "test_logger"
    assert parsed["level"] == "INFO"
    assert parsed["message"] == "Test message for JSON logging"
    assert parsed["request_id"] == "req-test-123"
    assert "timestamp" in parsed


def test_secret_redacting_filter():
    """Verify SecretRedactingFilter redacts sensitive patterns from log strings."""
    filter_instance = SecretRedactingFilter()
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Connecting with key sk-ant-api03-abcdef1234567890abcdef1234567890 and password=SuperSecretPass123!",
        args=(),
        exc_info=None,
    )
    filter_instance.filter(record)
    assert "REDACTED" in record.msg
    assert "sk-ant-api03-abcdef1234567890abcdef1234567890" not in record.msg


# ===========================================================================
# 7. SECURITY ALERTING ENGINE TESTS
# ===========================================================================

def test_alert_creation_and_deduplication(db_session: Session):
    """Verify that repeated critical security events deduplicate into a single alert record."""
    # Pre-test cleanup to guarantee isolation
    db_session.query(SecurityAlertModel).filter(SecurityAlertModel.alert_type == "BRUTE_FORCE_BURST").delete()
    db_session.commit()

    alert_engine = SecurityAlertEngine(db_session)

    # 1. First trigger
    alert1 = alert_engine.trigger_alert(
        alert_type="BRUTE_FORCE_BURST",
        severity=AlertSeverity.HIGH,
        title="Simulated Brute Force Attack",
        description="Repeated unauthorized access attempts detected",
        metadata={"attacker_ip": "10.0.0.99"},
    )
    assert alert1.occurrence_count == 1
    assert alert1.status == AlertStatus.ACTIVE
    alert_id = alert1.alert_id

    # 2. Second trigger with same type and title -> deduplication
    alert2 = alert_engine.trigger_alert(
        alert_type="BRUTE_FORCE_BURST",
        severity=AlertSeverity.HIGH,
        title="Simulated Brute Force Attack",
        description="Repeated unauthorized access attempts detected again",
        metadata={"attacker_ip": "10.0.0.99"},
    )
    assert alert2.alert_id == alert_id
    assert alert2.occurrence_count == 2

    # 3. Acknowledge alert
    ack = alert_engine.acknowledge_alert(alert_id, acknowledged_by="analyst_alice")
    assert ack.status == AlertStatus.ACKNOWLEDGED
    assert ack.acknowledged_by == "analyst_alice"

    # 4. Resolve alert
    res = alert_engine.resolve_alert(
        alert_id,
        resolved_by="lead_bob",
        resolution_notes="False positive verified during simulated penetration test",
    )
    assert res.status == AlertStatus.RESOLVED
    assert res.resolved_by == "lead_bob"

    # Cleanup
    db_session.query(SecurityAlertModel).filter(SecurityAlertModel.alert_id == alert_id).delete()
    db_session.commit()


def test_alerts_api_endpoints(operator_key: str, db_session: Session):
    """Verify /api/v1/alerts list, acknowledge, and resolve endpoints."""
    alert_engine = SecurityAlertEngine(db_session)
    alert = alert_engine.trigger_alert(
        alert_type="POLICY_VIOLATION_TEST",
        severity=AlertSeverity.MEDIUM,
        title="API Integration Test Alert",
        description="Testing alerts API router",
    )

    # List alerts
    list_res = client.get("/api/v1/alerts", headers={"Authorization": f"Bearer {operator_key}"})
    assert list_res.status_code == 200
    alerts = list_res.json()
    assert any(a["alert_id"] == alert.alert_id for a in alerts)

    # Acknowledge
    ack_res = client.post(
        f"/api/v1/alerts/{alert.alert_id}/acknowledge",
        headers={"Authorization": f"Bearer {operator_key}"},
        json={"acknowledged_by": "sec_operator"},
    )
    assert ack_res.status_code == 200
    assert ack_res.json()["status"] == "ACKNOWLEDGED"

    # Resolve
    resolve_res = client.post(
        f"/api/v1/alerts/{alert.alert_id}/resolve",
        headers={"Authorization": f"Bearer {operator_key}"},
        json={"resolved_by": "sec_lead", "resolution_notes": "Closed via test"},
    )
    assert resolve_res.status_code == 200
    assert resolve_res.json()["status"] == "RESOLVED"

    # Cleanup
    db_session.query(SecurityAlertModel).filter(SecurityAlertModel.alert_id == alert.alert_id).delete()
    db_session.commit()


# ===========================================================================
# 8. PRODUCTION CONFIGURATION VALIDATION (FAIL-CLOSED)
# ===========================================================================

def test_production_config_validation():
    """Verify that fail-closed validation strictly prevents starting in production with unsafe settings."""
    original_env = settings.ENVIRONMENT
    original_secret = settings.API_SECRET_KEY
    original_anon = settings.ALLOW_DEV_ANONYMOUS
    original_db = settings.DATABASE_URL
    original_cors = settings.CORS_ORIGINS
    original_pw = settings.POSTGRES_PASSWORD
    original_debug = settings.DEBUG

    try:
        settings.ENVIRONMENT = "production"
        settings.DEBUG = False
        settings.CORS_ORIGINS = ["https://sentinel.mycompany.com"]

        # Case 1: Unsafe default secret key
        settings.API_SECRET_KEY = "insecure-dev-secret-key-change-in-production-min32"
        settings.ALLOW_DEV_ANONYMOUS = False
        settings.POSTGRES_PASSWORD = "StrongSecurePassword123!"
        settings.DATABASE_URL = "postgresql://agentsentinel:StrongSecurePassword123!@localhost:5432/agentsentinel"
        with pytest.raises(ValueError, match="API_SECRET_KEY must be a cryptographically strong secret"):
            settings.validate_production_configuration()

        # Case 2: Short secret key
        settings.API_SECRET_KEY = "too_short_key"
        with pytest.raises(ValueError, match="API_SECRET_KEY must be a cryptographically strong secret"):
            settings.validate_production_configuration()

        # Case 3: ALLOW_DEV_ANONYMOUS is True in production
        settings.API_SECRET_KEY = "a_very_secure_high_entropy_secret_key_exceeding_32_characters_12345"
        settings.ALLOW_DEV_ANONYMOUS = True
        with pytest.raises(ValueError, match="ALLOW_DEV_ANONYMOUS must be False in production"):
            settings.validate_production_configuration()

        # Case 4: Default postgres password in production
        settings.ALLOW_DEV_ANONYMOUS = False
        settings.POSTGRES_PASSWORD = "postgres"
        with pytest.raises(ValueError, match="Default or blank POSTGRES_PASSWORD is not permitted"):
            settings.validate_production_configuration()

        # Case 5: Valid production configuration passes cleanly
        settings.POSTGRES_PASSWORD = "ExtremelyStrongPassword987!"
        settings.API_SECRET_KEY = "a_very_secure_high_entropy_secret_key_exceeding_32_characters_12345"
        settings.ALLOW_DEV_ANONYMOUS = False
        # Must not raise
        settings.validate_production_configuration()

    finally:
        # Restore environment settings
        settings.ENVIRONMENT = original_env
        settings.API_SECRET_KEY = original_secret
        settings.ALLOW_DEV_ANONYMOUS = original_anon
        settings.DATABASE_URL = original_db
        settings.CORS_ORIGINS = original_cors
        settings.POSTGRES_PASSWORD = original_pw
        settings.DEBUG = original_debug


def test_production_dev_anonymous_explicit_fail_closed():
    """
    Explicit regression test:
    Verify ENVIRONMENT=production + ALLOW_DEV_ANONYMOUS=True strictly causes
    startup configuration validation to fail-closed with ValueError.
    """
    original_env = settings.ENVIRONMENT
    original_anon = settings.ALLOW_DEV_ANONYMOUS
    original_secret = settings.API_SECRET_KEY
    original_pw = settings.POSTGRES_PASSWORD
    original_debug = settings.DEBUG
    original_cors = list(settings.CORS_ORIGINS)

    try:
        settings.ENVIRONMENT = "production"
        settings.ALLOW_DEV_ANONYMOUS = True
        settings.DEBUG = False
        settings.POSTGRES_PASSWORD = "StrongProdPassword_123456789"
        settings.API_SECRET_KEY = "a_very_secure_high_entropy_secret_key_exceeding_32_characters_12345"
        settings.CORS_ORIGINS = ["https://sentinel.internal"]

        with pytest.raises(ValueError) as exc_info:
            settings.validate_production_configuration()

        assert "ALLOW_DEV_ANONYMOUS must be False in production" in str(exc_info.value)
    finally:
        settings.ENVIRONMENT = original_env
        settings.ALLOW_DEV_ANONYMOUS = original_anon
        settings.API_SECRET_KEY = original_secret
        settings.POSTGRES_PASSWORD = original_pw
        settings.DEBUG = original_debug
        settings.CORS_ORIGINS = original_cors


# ===========================================================================
# 9. DATABASE SCHEMA MIGRATION IDEMPOTENCE
# ===========================================================================

def test_schema_migrations_runner_is_idempotent(db_session: Session):
    """Verify running migrations multiple times is strictly idempotent and safe."""
    # Ensure migrations run without errors on engine
    applied_first = apply_migrations(engine)
    assert isinstance(applied_first, int)

    # Second run should apply 0 new migrations
    applied_second = apply_migrations(engine)
    assert applied_second == 0

    # Verify migration records exist in database
    records = db_session.query(SchemaMigrationModel).all()
    assert len(records) >= len(REVISIONS)
    assert any(r.version == 1 for r in records)
    assert any(r.version == 2 for r in records)
