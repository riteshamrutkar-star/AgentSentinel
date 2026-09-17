# AgentSentinel — Production Deployment & Operations Guide

> **Architecture Status**: Operationally Hardened & Deployment-Ready Foundation (Phase 0.8)  
> **Notice**: AgentSentinel provides a hardened operational control plane. In accordance with rigorous operational principles, AgentSentinel is described as a **production-oriented foundation**, not a blanket "enterprise-ready" solution.

---

## 1. Architectural Topology

In a production environment, AgentSentinel deploys across segregated network zones to ensure minimal attack surface, least-privilege isolation, and defense-in-depth.

```text
[ External Clients / LLM Orchestrators / SOC Operators ]
                           │
                           ▼ (Port 80 / 443 TLS)
             ┌───────────────────────────┐
             │    Nginx Ingress Proxy    │
             │  - TLS Termination        │
             │  - Ingress Rate Limiting  │
             │  - Request ID Generation  │
             │  - Security Headers       │
             └─────────────┬─────────────┘
                           │ (sentinel-frontend network)
            ┌──────────────┴──────────────┐
            ▼                             ▼
  ┌───────────────────┐         ┌───────────────────┐
  │ React Dashboard   │         │ Backend Control   │
  │ (Static SPA on    │         │ Plane (ASGI)      │
  │  Nginx Alpine)    │         │ - Port 8000       │
  └───────────────────┘         │ - 4 Uvicorn Wkrs  │
                                │ - Non-root 10001  │
                                └─────────┬─────────┘
                                          │ (sentinel-internal network)
                                          ▼
                                ┌───────────────────┐
                                │   PostgreSQL 17   │
                                │ - Isolated DB     │
                                │ - Bounded Pool    │
                                └───────────────────┘
```

### Key Architectural Isolation Rules
1. **Database Isolation**: PostgreSQL is placed exclusively on `sentinel-internal` and is never exposed to the public host or ingress network.
2. **Unprivileged Execution**: The backend container runs as dedicated user `agentsentinel` (UID 10001, GID 10001) with `no-new-privileges:true`.
3. **Fail-Closed Configuration**: In `ENVIRONMENT=production`, any missing or default secret (`API_SECRET_KEY`, weak DB password, or `ALLOW_DEV_ANONYMOUS=true`) causes an immediate process startup crash.

---

## 2. Environment Variables & Secret Configuration

Production deployments must supply a secure `.env` file. Never commit `.env` to source control.

| Environment Variable | Required in Prod | Default | Description |
|---|:---:|:---:|---|
| `ENVIRONMENT` | **Yes** | `development` | Must be explicitly set to `production`. |
| `API_SECRET_KEY` | **Yes** | *None* | High-entropy secret (min 32 chars) used for HMAC-SHA-256 API key hashing and session signatures. |
| `DATABASE_URL` | **Yes** | *None* | PostgreSQL connection string (`postgresql://user:pass@host:5432/db`). |
| `POSTGRES_PASSWORD` | **Yes** | *None* | Secure database password. |
| `ALLOW_DEV_ANONYMOUS` | **Yes** | `false` | Must be `false` in production. Unauthenticated requests are rejected with HTTP 401. |
| `RATE_LIMIT_ENABLED` | No | `true` | Enables token-bucket rate limiting. |
| `RATE_LIMIT_REQUESTS_PER_MINUTE` | No | `60` | Token generation rate per client IP. |
| `RATE_LIMIT_BURST` | No | `10` | Maximum token bucket burst capacity. |
| `MAX_REQUEST_SIZE_BYTES` | No | `10485760` | Payload limit (10MB default) to prevent memory exhaustion DoS. |
| `DB_POOL_SIZE` | No | `10` | SQLAlchemy connection pool size. |
| `DB_MAX_OVERFLOW` | No | `20` | SQLAlchemy connection pool maximum overflow. |
| `LOG_FORMAT` | No | `json` | Structured JSON logging for Datadog, CloudWatch, or Splunk ingestion. |
| `LOG_LEVEL` | No | `INFO` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`). |

---

## 3. Administrative RBAC Roles

AgentSentinel distinguishes between **Agent Tool Authorization** (governed by the Interceptor policy engine) and **Administrative Operator Authorization** (governed by API Keys):

| Role | Weight | Permissions |
|---|:---:|---|
| `VIEWER` | 10 | Read-only access to audit logs, events, metrics, and health endpoints. |
| `OPERATOR` | 20 | All `VIEWER` permissions + Approve / Reject pending human-in-the-loop tool actions, acknowledge alerts. |
| `SECURITY_ADMIN` | 30 | All `OPERATOR` permissions + Resolve security alerts, trigger attack simulations, configure behavioral thresholds. |
| `PLATFORM_ADMIN` | 40 | Full control plane access + Create, list, and revoke administrative API keys. |

### API Key Format
- Production Live Keys: `as_live_<48-character-hex-entropy>`
- Test Environment Keys: `as_test_<48-character-hex-entropy>`
- Storage: Raw keys are displayed **once** at creation. Only the HMAC-SHA-256 hash is persisted in the `api_keys` table.

---

## 4. Rate Limiting Architecture & Limitations

AgentSentinel implements a thread-safe sliding-window token bucket in `app.core.ratelimit.InMemoryRateLimiter`.

> [!WARNING]
> **Single-Instance Limitation**:  
> The built-in rate limiter is strictly in-memory per container process. It does **NOT** provide distributed synchronization across horizontally scaled container instances.  
> - For single-node or vertical scaling deployments, it effectively prevents burst abuse and single-source resource starvation.
> - For horizontal multi-instance deployments behind a cluster load balancer, external coordinated rate limiting (e.g. at the Nginx Ingress or API Gateway layer) must be utilized.

---

## 5. Deployment Step-by-Step

### Step 1: Generate Secrets
```bash
# Generate high-entropy API secret key
python -c "import secrets; print(secrets.token_hex(32))"
```

### Step 2: Configure Environment
Create `.env.prod`:
```bash
ENVIRONMENT=production
API_SECRET_KEY=e83a9f014b28d73b5a19c92... # Use generated 64-character secret
POSTGRES_USER=agentsentinel
POSTGRES_PASSWORD=VerySecureDatabasePassword123!
POSTGRES_DB=agentsentinel
ALLOW_DEV_ANONYMOUS=false
RATE_LIMIT_ENABLED=true
LOG_FORMAT=json
```

### Step 3: Run Non-Destructive Migrations
Migrations execute automatically on application startup. To manually verify schema status:
```bash
python -m app.db.migrations
```

### Step 4: Launch Stack
```bash
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
```

### Step 5: Verify Multi-Stage Health Probes
```bash
# Process Liveness
curl -f http://localhost/health/live

# Deep Dependency Readiness
curl -f http://localhost/health/ready

# Inspect Dependencies
curl -f http://localhost/health/dependencies
```

### Step 6: Create Initial Platform Admin API Key
```bash
# Using Python CLI script or bootstrap tool:
python -c "
from app.db.session import SessionLocal
from app.auth.service import ApiKeyService
from app.auth.models import AdminRole
db = SessionLocal()
key, token = ApiKeyService.create_key(db, 'Bootstrap Admin', AdminRole.PLATFORM_ADMIN)
print(f'Created Admin Key: {token}')
db.close()
"
```
Save the returned `as_live_...` token securely in your secrets vault.
