# AgentSentinel v1.0 — Security Threat Model

## 1. Scope & Assets

This document defines the formal security threat model for AgentSentinel v1.0 using the STRIDE methodology.

### Protected Assets
1. **Administrative & Operator Credentials**: API keys (`as_live_...`), OIDC JWT signing keys, operator session tokens.
2. **AI Agent Identities & Credentials**: Registered agent identities, capability grants, and delegation tokens.
3. **Security Policies**: RBAC and ABAC policy rules governing permitted and prohibited tool execution.
4. **Audit Logs & Security Events**: Authoritative immutable security event history, trace IDs, and execution records.
5. **Execution Gateway & Host Compute**: Host operating system, filesystem paths, network interfaces, and process execution capabilities.
6. **Application Secrets**: Database credentials, Redis secrets, webhook HMAC signing keys, and external API keys.
7. **Namespace Boundaries**: Tenant-isolated data and execution environments across 11 PostgreSQL tables.
8. **Historical Research & Benchmark Evidence**: Reproducibility manifests, experiment baselines, and evaluation datasets.

---

## 2. Threat Actors & Capabilities

- **External Network Adversary**: Unauthenticated or credential-stuffing attacker attempting ingress exploitation.
- **Compromised AI Agent**: An LLM agent compromised via prompt injection, goal hijacking, or jailbreak attempts.
- **Malicious Internal Operator**: Operator attempting privilege escalation beyond assigned role or unauthorized cross-namespace queries.
- **Malicious Ecosystem Tool**: Third-party tool returning malicious payloads, shell injection strings, or SSRF requests.
- **Rogue Multi-Agent Subagent**: Delegated subagent attempting capability escalation or circular delegation loops.

---

## 3. STRIDE Threat Analysis & Defense Mapping

| Threat Category | Specific Threat Scenario | Primary Defensive Control | Failure / Edge Behavior |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Forged JWT operator token | Asymmetric RS256 validation against trusted JWKS; strict rejection of HS256 algorithm confusion | HTTP 401 Unauthorized |
| **Spoofing** | Agent identity masquerade | Cryptographic delegation tokens with cryptographic signature and provenance validation | Fails closed; tool blocked |
| **Tampering** | Webhook payload tampering / replay | HMAC-SHA-256 signatures with timestamp window check ($\pm 300\text{s}$) | HTTP 401 / 400 rejection |
| **Tampering** | Multi-instance database migration race | PostgreSQL advisory locking `pg_advisory_lock(84729103)` | Serialized execution |
| **Repudiation** | Denial of unauthorized action | Transactional outbox pattern committing audit events in same DB transaction as policy verdict | Immutable PostgreSQL log |
| **Information Disclosure** | Tool execution secret leakage | Post-execution regex and entropy-based secret redaction engine | Output masked before return |
| **Information Disclosure** | Cross-tenant data leakage | Persisted namespace column across 11 tables with SQL-level enforcement | HTTP 403 Forbidden |
| **Denial of Service** | API request floods & replay storm | Distributed sliding-window rate limiting via Redis Lua scripts + scoped idempotency cache | HTTP 429 Too Many Requests |
| **Elevation of Privilege**| Delegated subagent capability expansion | Attenuation invariant: child capabilities must be strict subset of parent capabilities | Denied; delegation blocked |
| **Elevation of Privilege**| Human operator acting as agent directly | Bidirectional privilege separation (`enforce_operator_isolation`) | HTTP 403 Forbidden |

---

## 4. Residual Risks & Documented Limitations

1. **Redis Coordinator Single Point of Failure**: State coordination depends on a single Redis 7 coordinator. In production, Redis outages fail closed for mutating calls, causing downtime for protected operations until restored.
2. **PostgreSQL Primary Single Point of Failure**: Outages of the primary database halt write transactions and audit logging. The platform is not an automated failover multi-AZ cluster.
3. **In-Process Local Sandbox Fallback**: When containerized Docker sandboxing is unavailable, execution defaults to the in-process sandbox runner which enforces path and executable restrictions but lacks kernel namespace isolation.
