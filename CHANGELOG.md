# Changelog

All notable changes to the AgentSentinel platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-09-19
### Unified AI-Agent Security Control Plane — Production Integration & Release

#### Added
- **Canonical Security Models (`CanonicalSecurityRequest`, `CanonicalSecurityDecision`)**:
  - Unified data models replacing fragmented representations across proxies, gateways, and ecosystem adapters.
  - Normalized action types, capability validation, and deterministic verdicts (`ALLOW`, `DENY`, `REQUIRE_APPROVAL`, `ERROR`).
- **Python Developer SDK Packaging (`sdk/`)**:
  - Standard `pyproject.toml` configuration with Setuptools build system.
  - Typed exception hierarchy (`SecurityBlockedError`, `ApprovalPendingError`, `RateLimitExceededError`, `ConnectionError`).
  - Zero local policy engine evaluation invariant; full control plane delegation.
- **AgentSentinel Command Line Interface (CLI)**:
  - Lightweight operational CLI utility (`python -m app.cli.main`) with subcommands: `health`, `auth`, `namespaces`, `agents`, `policies`, `alerts`, `events`, `benchmark`.
- **17-Vector Security Invariant Regression Suite (`backend/tests/test_v10_security_invariants.py`)**:
  - Automated regression tests covering prompt manipulation, unauthorized tools, cross-namespace denial, privilege escalation, delegation abuse, irrevocable policy deny, execution bypass, path traversal, network egress, secret redaction, webhook replay, credential revocation, OIDC confusion, idempotency replay, distributed lock exclusion, adapter fail-closed, and SDK fail-closed.
- **Independent v1.0 Operational Benchmark Suite (`scripts/run_v10_benchmark.py`)**:
  - Evaluates Scenarios A through J across 550 samples with 98.18% aggregate accuracy (Scenario A benign tool operations at 90.0% accuracy; Scenarios B-J attack defenses at 100.0% accuracy).
  - Reports granular latency profiles: full interception pipeline at 11.17–16.81 ms median, and fast-path guards / authentication checks at 0.00–1.50 ms.
  - Generates `reports/benchmark_v1.0.json` and `reports/reproducibility_manifest_v1.0.json`.
- **Comprehensive Documentation Hierarchy (`docs/`)**:
  - `docs/architecture/reference_architecture.md`: Canonical reference architecture, request lifecycle, and data flow.
  - `docs/security/threat_model.md`: Formal STRIDE threat model, threat actors, and residual risk.
  - `docs/security/precedence_rules.md`: Deterministic precedence rules across security layers.
  - `docs/deployment/deployment_profiles.md`: Local dev, test/CI, single-node prod, and distributed prod deployment profiles.
  - `docs/api/api_inventory.md`: Complete standardized REST endpoint matrix.
  - `docs/adapters/framework_adapters.md`: Supported framework adapters guide and duck-typing fallback.
  - `docs/operations/incident_response_and_runbooks.md`: Failure recovery, backup/restore, and containment runbooks.
  - `docs/research/methodology.md`: Empirical research methodology, historical 80-scenario dataset taxonomy (45 train, 19 validation, 16 test), independent 550-sample v1.0 benchmark, and ablation analysis.

#### Changed
- Interceptor proxy and ecosystem adapters now evaluate canonical security requests and emit canonical security decisions.
- Enforced strict authorization boundaries: all physical tool executions must route through `SecureExecutionGateway`.
- Enforced `require_operator_identity` on admin and governance endpoints, preventing agent runtime tokens from modifying control plane configuration.
- Unified SOC dashboard version header to `v1.0.0-RELEASE` with 13 consolidated operational panels.
- System version bumped to `1.0.0` in `config.py` and `.env`.

#### Architectural Disclosures & Compliance
- **Framework Adapter Status**: Classified as `SUPPORTED` (LangChain, LangGraph, AutoGen, CrewAI, Semantic Kernel), validated via standardized mock harnesses and regression suites.
- **Single Points of Failure (SPOFs)**: Non-HA single Redis 7 coordinator and single PostgreSQL 17 primary database in standard deployment profile; fail-closed behavior enforced on outage.

---

## [0.9.0] - 2026-09-17
### Distributed Control Plane, Framework Adapters & Durable Namespaces
- Redis 7 distributed state backend, distributed locks, and sliding-window rate limiting.
- Scoped idempotency engine deduplicating concurrent replays.
- Durable PostgreSQL-backed transactional outbox and HMAC-SHA-256 signed webhooks.
- Multi-framework adapters for LangChain, LangGraph, AutoGen, CrewAI, and Semantic Kernel.
- OIDC identity federation for human operators with RS256 token validation.
- Durable PostgreSQL multi-tenant namespace isolation across all security entities.

---

## [0.8.0] - 2026-09-12
### Production Hardening, Authentication & Observability
- API key authentication with HMAC-SHA-256 hashing, key prefixing, and expiration.
- Administrative RBAC roles: `VIEWER`, `OPERATOR`, `SECURITY_ADMIN`, `PLATFORM_ADMIN`.
- In-memory sliding-window token bucket rate limiting with HTTP 429 Retry-After.
- API security hardening: Security Headers, Request ID/Correlation ID middleware, payload limits.
- Multi-stage health probes (`/health/live`, `/health/ready`, `/health/dependencies`).
- Prometheus metrics exposition (`/metrics`) and structured JSON logging.
- Deduplicating security alerting engine and Alembic database migrations.

---

## [0.7.0] - 2026-09-11
### Empirical Evaluation & Research Methodology
- Standardized 80-scenario benchmark dataset (45 train, 19 validation, 16 test) spanning adversarial threat categories.
- Comparative evaluation of Systems A, B, C, and D ($F_1 = 0.902$).
- Component ablation study and latency profiling across control plane layers.
- Research dataset immutability manifests and reproducible evaluation harness.

---

## [0.6.0] - 2026-08-11
### Attack Simulation & Threat Taxonomy
- 25 standard attack scenarios mapped to OWASP LLM Top 10 and MITRE ATLAS.
- Synthetic adversarial prompt injection generator.
- Controlled attack simulation runner and defensive verification harness.

---

## [0.5.0] - 2026-08-11
### Secure Execution Gateway & Sandboxing
- Authoritative execution gateway with 14-stage pre-execution checks.
- Filesystem sandbox preventing path traversal and protected OS file access.
- Network egress guard blocking raw IPs, cloud metadata endpoints, and exfiltration sinks.
- Secret protection layer sanitizing credentials and API keys in execution output.

---

## [0.4.0] - 2026-08-11
### Multi-Agent Governance & Delegation Attenuation
- Agent identity registry and capability envelope assignment.
- Cryptographic delegation tokens with capability attenuation and depth bounding.
- Privilege escalation detection and circular delegation loop prevention.

---

## [0.3.0] - 2026-08-10
### Advanced Behavioral Anomaly Detection
- Stateful sliding-window sequence, burst, role, and transition detectors.
- Unified Bayesian risk scoring engine with explainable threat indicators.

---

## [0.2.0] - 2026-08-06
### Security Hardening & Fail-Closed Controls
- Default-deny / fail-closed error handling across interception pipeline.
- Database indexing, connection pooling, and error sanitization.

---

## [0.1.0] - 2026-08-04
### Initial Control Plane Foundations
- Runtime interception of agent tool calls.
- Security event lifecycle and audit logging.
- Declarative policy enforcement and asynchronous human approval workflows.
- Baseline behavioral monitoring and initial web dashboard.
