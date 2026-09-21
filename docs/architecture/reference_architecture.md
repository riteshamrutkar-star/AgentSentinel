# AgentSentinel v1.0 — Reference Architecture

## 1. Executive Architecture Overview

AgentSentinel v1.0 is a unified, horizontally coordinated runtime security control plane designed to enforce authorization, policy guardrails, behavioral anomaly detection, multi-agent governance, and sandboxed tool execution for AI agents.

```
                           AI AGENTS / OPERATORS / CLIENTS
                                          │
                                          ▼
                      ┌───────────────────────────────────────┐
                      │          INGRESS / API GATEWAY        │
                      │     Reverse Proxy & TLS Termination   │
                      └───────────────────┬───────────────────┘
                                          │
                         ┌────────────────┴────────────────┐
                         ▼                                 ▼
              ┌─────────────────────┐           ┌─────────────────────┐
              │   HUMAN IDENTITY    │           │   AGENT IDENTITY    │
              │  OIDC JWT / API Key │           │  Trust / Capability │
              │  Administrative RBAC│           │  Delegation Token   │
              └──────────┬──────────┘           └──────────┬──────────┘
                         │                                 │
                         └────────────────┬────────────────┘
                                          │
                                          ▼
                         ┌─────────────────────────────────┐
                         │      NAMESPACE AUTHORIZATION    │
                         │   Default-Deny Tenancy Boundary │
                         └────────────────┬────────────────┘
                                          │
                                          ▼
                         ┌─────────────────────────────────┐
                         │      SECURITY CONTROL PLANE     │
                         │   Canonical Security Pipeline   │
                         └────────────────┬────────────────┘
                                          │
                 ┌────────────────────────┼────────────────────────┐
                 ▼                        ▼                        ▼
      ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐
      │    POLICY ENGINE    │  │   BEHAVIORAL RISK   │  │ MULTI-AGENT GOVERN  │
      │   RBAC / ABAC Rules │  │   Anomaly Detectors │  │ Attenuation / Trusts│
      └──────────┬──────────┘  └──────────┬──────────┘  └──────────┬──────────┘
                 │                        │                        │
                 └────────────────────────┼────────────────────────┘
                                          │
                                          ▼
                         ┌─────────────────────────────────┐
                         │   APPROVAL & EXECUTION GATEWAY  │
                         │     14 Mandatory Gate Checks    │
                         └────────────────┬────────────────┘
                                          │
                                          ▼
                         ┌─────────────────────────────────┐
                         │         SANDBOX RUNNER          │
                         │   Filesystem / Network / Proc   │
                         └────────────────┬────────────────┘
                                          │
                                          ▼
                         ┌─────────────────────────────────┐
                         │    OUTPUT SECURITY & AUDIT      │
                         │    Secret Redaction / Event     │
                         └────────────────┬────────────────┘
                                          │
                         ┌────────────────┴────────────────┐
                         ▼                                 ▼
             ┌───────────────────────┐         ┌───────────────────────┐
             │ POSTGRESQL 17 PRIMARY │         │  TRANSACTIONAL OUTBOX │
             │  Authoritative Truth  │         │  Async Egress Queue   │
             │  Durable Namespaces   │         └───────────┬───────────┘
             └───────────────────────┘                     │
                                           ┌───────────────┼───────────────┐
                                           ▼               ▼               ▼
                                    ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
                                    │ Webhook Svc │ │  SIEM Stream│ │Internal Ops │
                                    └─────────────┘ └─────────────┘ └─────────────┘
```

---

## 2. Core Architectural Invariants

1. **Durable Namespace Boundary**:
   Tenant separation is persisted in PostgreSQL across 11 core tables (`sessions`, `security_events`, `policies`, `agents`, `delegations`, `executions`, `approvals`, `security_findings`, `security_alerts`, `event_outbox`, `webhook_deliveries`).
   $$\text{Requested Namespace} \notin \text{Principal Authorized Namespaces} \implies \text{HTTP 403 Forbidden}$$

2. **Deterministic Precedence Enforcement**:
   - Namespace authorization precedes policy evaluation.
   - An explicit static policy `DENY` is irrevocable and cannot be weakened by behavioral detection, human approvals, or multi-agent delegation.
   - Behavioral detection may escalate enforcement (`ALLOW` $\rightarrow$ `REQUIRE_APPROVAL` or `DENY`), but can never weaken a `DENY`.
   - Human approvals can only transition a `REQUIRE_APPROVAL` state to `APPROVED`; they cannot overturn an explicit policy `DENY`.
   - Multi-agent delegation can only attenuate or reduce capabilities; it can never escalate permissions beyond the delegator.

3. **Authoritative Execution Boundary**:
   All physical tool execution must pass through `SecureExecutionGateway`. There are no unmediated execution backdoors.

4. **Single Point of Failure (SPOF) Transparency**:
   AgentSentinel coordinates active-active application replicas behind Nginx. Coordination (rate limiting, distributed locks, idempotency) relies on a **single Redis 7 coordinator**, and durability relies on a **single PostgreSQL 17 primary database**. The platform is not a multi-region or automated-failover HA cluster.
