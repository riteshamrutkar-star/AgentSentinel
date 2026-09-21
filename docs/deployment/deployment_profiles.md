# AgentSentinel v1.0 — Deployment Profiles

## 1. Overview of Deployment Profiles

AgentSentinel supports four distinct deployment profiles depending on the target environment:

| Profile | Target | Database | Coordinator | Ingress | Rate Limiter | Fail-Closed |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: |
| **1. Local Development** | Developer workstation | PostgreSQL 17 or SQLite | In-Memory (Local) | Direct FastAPI | Local In-Memory | Disabled (Dev Anon Allowed) |
| **2. Test / CI** | Automated test pipelines | Test PostgreSQL / In-Memory | In-Memory (Local) | TestClient | Local In-Memory | Configurable |
| **3. Single-Node Production**| Staging / Edge Deployments | Standalone PostgreSQL 17 | In-Memory (Local, 1 worker) | Reverse Proxy / TLS | Instance-Local | Enabled |
| **4. Distributed Production**| Multi-instance Cluster | Standalone PostgreSQL 17 | Shared Redis 7 Alpine | Nginx Load Balancer | Redis Distributed | Enabled |

---

## 2. Profile Details & Requirements

### Profile 1: Local Development
- Command: `uvicorn app.main:app --reload --port 8000`
- `ALLOW_DEV_ANONYMOUS=True` permits unauthenticated developer testing.
- `DEBUG=True`.

### Profile 2: Test / CI
- Command: `pytest backend/tests -v`
- Ephemeral test databases with automatic teardown.
- `TESTING=True`.

### Profile 3: Single-Node Production-Oriented
- Docker Compose single backend container.
- Rate limiter runs process-locally with a single worker (`UVICORN_WORKERS=1`) to ensure effective instance-level quota enforcement.
- `ALLOW_DEV_ANONYMOUS=False`. Strong `API_SECRET_KEY` enforced.

### Profile 4: Distributed Production-Oriented
- Coordinates active-active replicas (`backend-1`, `backend-2`) behind an Nginx round-robin load balancer.
- Coordination layer: Redis 7 Alpine for atomic sliding-window rate counters, mutual exclusion locks (`DistributedLock`), and idempotency caching.
- Durability layer: Authoritative PostgreSQL 17 primary instance with transactional outbox and durable webhook tables.
- **SPOF Notice**: Relies on a single Redis coordinator and a single PostgreSQL primary. It is not an automated failover HA cluster.
