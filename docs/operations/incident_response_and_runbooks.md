# AgentSentinel v1.0: Operations & Incident Response Runbooks

## 1. Overview and Incident Management Lifecycle

AgentSentinel operates as a centralized security control plane mediating autonomous AI agent actions. When operational disruptions or security incidents occur, operations teams must follow structured runbooks to preserve integrity, contain compromises, and restore verified operations.

`mermaid
flowchart LR
    Detect[1. Detect & Triage] --> Contain[2. Containment]
    Contain --> Eradicate[3. Remediation]
    Eradicate --> Recover[4. Recovery]
    Recover --> PostMortem[5. Post-Mortem]
`

### Severity Definitions
- **SEV-1 (Critical)**: Control plane fail-closed state preventing business-critical tool executions; database or Redis cluster outage; confirmed unauthorized privilege escalation or data exfiltration across namespace boundaries.
- **SEV-2 (High)**: Individual agent behavioral anomaly burst; failed webhook delivery outbox threshold exceeded; elevated tool execution failure rate (>5%).
- **SEV-3 (Moderate)**: Rate-limit exhaustion on non-critical endpoints; delayed audit ingestion; intermittent sandbox worker restarts.
- **SEV-4 (Low)**: Informational policy violations logged; non-blocking configuration warnings.

---

## 2. Infrastructure Failure & Recovery Runbooks

### 2.1 Redis Coordinator Outage (SEV-1)
**Symptom**: Interceptor requests receive 503 Service Unavailable or 500 Internal Error (when fail-closed is active); Redis connection pool timeouts in backend logs.

**Root Cause**: Redis service termination, memory exhaustion (OOM), or network partition. Note that v1.0 standard deployment utilizes a single Redis 7 coordinator (Single Point of Failure).

**Recovery Steps**:
1. Check Redis process status:
   docker compose -f docker-compose.prod.yml ps redis
2. Inspect Redis logs:
   docker compose -f docker-compose.prod.yml logs --tail=100 redis
3. If container crashed or OOMKilled, restart the service:
   docker compose -f docker-compose.prod.yml restart redis
4. Test Redis responsiveness via CLI:
   python -m app.cli.main health
5. Verify distributed lock lease reclamation and normal proxy interception resumption.

---

### 2.2 PostgreSQL Primary Outage (SEV-1)
**Symptom**: Control plane rejects all requests with database connection errors; transactional outbox and policy lookups fail.

**Recovery Steps**:
1. Check PostgreSQL container health:
   docker compose -f docker-compose.prod.yml ps db
2. Verify persistent volume disk space on the host machine.
3. Restart the database container if inactive:
   docker compose -f docker-compose.prod.yml restart db
4. Verify database connectivity:
   python -m app.cli.main health
5. If data corruption is detected, invoke the Disaster Recovery Restore procedure detailed in Section 3.

---

## 3. Backup and Disaster Recovery

AgentSentinel includes an automated backup utility (scripts/backup_restore.py) supporting full schema, metadata, policy, and audit trail retention.

### 3.1 Creating an On-Demand Backup
python scripts/backup_restore.py --action backup --namespace production --output backups/manual_snapshot.sql

### 3.2 Restoring from Backup
Restoring a database snapshot overwrites existing table records. Ensure target instances are drained of active agent traffic before restoration.

1. Drain active agent traffic:
   docker compose -f docker-compose.prod.yml stop backend
2. Execute restore command:
   python scripts/backup_restore.py --action restore --input backups/target_snapshot.sql
3. Run Alembic migration verification:
   alembic upgrade head
4. Restart backend application services:
   docker compose -f docker-compose.prod.yml start backend
5. Run health check verification:
   python -m app.cli.main health

---

## 4. Security Incident Runbooks

### 4.1 Compromised Agent Containment & Revocation (SEV-1 / SEV-2)
**Trigger**: An autonomous agent exhibits prompt injection symptoms, unapproved high-risk tool calling, or anomalous capability expansion.

**Immediate Actions**:
1. Revoke Agent Registration via CLI:
   python -m app.cli.main agents revoke <AGENT_ID> --namespace <NAMESPACE>
2. Cascade Delegation Invalidation:
   Revoking the root agent automatically invalidates all descendant delegated tokens within the multi-agent graph.
3. Terminate Active Sandbox Executions:
   Inspect active sandbox worker containers and kill executions associated with the agent session ID.
4. Audit Affected Event Logs:
   python -m app.cli.main events --agent <AGENT_ID> --limit 100

---

### 4.2 Cross-Namespace Boundary Violation (SEV-1)
**Trigger**: Security alert indicating CROSS_NAMESPACE_ACCESS_ATTEMPT or HTTP 403 authorization failures on scoped data.

**Actions**:
1. Identify the offending principal token (API key or OIDC token exchange).
2. Confirm default-deny authorization blocked execution in security_events table.
3. Revoke offending API credentials or disable compromised OIDC client ID.
4. Review namespace authorization mapping in PostgreSQL namespaces table.

---

### 4.3 Secret Leakage & Exfiltration Redaction (SEV-2)
**Trigger**: Execution gateway output redactor flags pattern match (CREDENTIAL_LEAKAGE_DETECTED, AWS_SECRET_KEY, BEARER_TOKEN).

**Actions**:
1. Check the sanitized execution response in executions table.
2. Confirm that sensitive text was redacted with [REDACTED_SECRET_*].
3. Rotate the compromised credential in the external source system immediately.
4. Identify which tool produced the unmasked secret and review its input arguments.

---

### 4.4 Webhook Outbox Delivery Backlog (SEV-3)
**Trigger**: SIEM or external webhook alert queue depth exceeds 1,000 pending items.

**Actions**:
1. Check webhook health status:
   python -m app.cli.main alerts
2. Verify network egress reachability to external webhook endpoints.
3. Check worker container logs for TLS or HTTP timeout errors.
4. Re-queue or retry failed messages once downstream SIEM receiver connectivity is restored.
