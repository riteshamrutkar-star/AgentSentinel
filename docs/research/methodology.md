# AgentSentinel: Research Methodology & Empirical Evaluation Framework

## 1. Overview and Scientific Motivation

Autonomous AI agents equipped with tool-execution capabilities present a novel threat landscape where non-deterministic reasoning can be subverted via prompt injection, privilege escalation, delegation chaining, and secret exfiltration. 

The AgentSentinel research framework evaluates defensive efficacy using empirical, reproducible benchmarks across multi-layered control plane architectures, cleanly separating historical research baselines from production release operational benchmarks.

---

## 2. Historical Phase 0.7 Research Evaluation

### 2.1 Historical Research Dataset
The historically verified Phase 0.7 research dataset (`research/datasets/dataset-v1.0.jsonl`) comprises **80 standardized scenarios** partitioned deterministically:

| Split | Scenario Count | Proportion | Purpose |
|---|---|---|---|
| **TRAIN** | 45 | 56.25% | Baseline policy and behavioral detector tuning |
| **VALIDATION** | 19 | 23.75% | Anomaly threshold and hyperparameter optimization |
| **TEST** | 16 | 20.00% | Final out-of-sample empirical evaluation |
| **Total** | **80** | **100.0%** | **Historical Research Benchmark Corpus** |

The 80 scenarios span benign operational behaviors and key adversarial threat vectors including direct prompt injection, privilege escalation, delegation chaining, tool manipulation, secret exfiltration, filesystem traversal, and unauthorized cross-namespace access.

### 2.2 Comparative Architectural Systems
The empirical evaluation benchmarked four defense architectures across identical historical workloads:

1. **System A (Unprotected Agent Baseline)**: Raw agent tool execution without mediation or policy validation. All tool calls execute directly in the host context.
2. **System B (Static Policy-Only Interceptor)**: Regex and rule-based policy gate with deterministic allow/deny rules. Lacks stateful behavioral anomaly detection and multi-agent delegation context.
3. **System C (Heuristic Anomaly Detection)**: Unsupervised statistical burst and sequence detector. Lacks declarative access control policies and cryptographic delegation verification.
4. **System D (Unified Multi-Layer Control Plane - AgentSentinel)**: Co-designed architecture integrating durable namespace boundary isolation, deterministic static policy enforcement, stateful behavioral anomaly scoring, cryptographic delegation capability attenuation, and sandboxed execution with output sanitization.

### 2.3 Historical Empirical Results

Evaluated on the standardized 80-scenario dataset under reproducible random seeds (SEED=42):

| Architecture | Precision | Recall | F1-Score | Specificity |
|---|---|---|---|---|
| **System A (Baseline)** | 0.000 | 0.000 | 0.000 | 1.000 |
| **System B (Static Policy)** | 0.912 | 0.583 | 0.711 | 0.978 |
| **System C (Behavioral Only)** | 0.748 | 0.715 | 0.731 | 0.895 |
| **System D (AgentSentinel Historical)** | **0.942** | **0.865** | **0.902** | **0.985** |

### 2.4 Component Ablation Analysis
Ablation experiments on the historical dataset evaluated the marginal contribution of each security layer:

| Configuration | F1-Score | Delta vs Full | Vulnerability Exposed |
|---|---|---|---|
| **Full Architecture (System D)** | **0.902** | Baseline | None |
| w/o Behavioral Detection | 0.711 | -0.191 | Sophisticated low-and-slow / novel attacks |
| w/o Delegation Attenuation | 0.814 | -0.088 | Confused deputy and child agent escalation |
| w/o Output Sanitization | 0.856 | -0.046 | Downstream secret exfiltration via stdout |
| w/o Namespace Isolation | 0.789 | -0.113 | Cross-tenant memory and data leakage |

---

## 3. Independent v1.0 Operational Benchmark

To validate the consolidated v1.0 control plane under production conditions without contaminating historical research baselines, an **independent operational benchmark suite** of **550 samples** across Scenarios A through J was executed (`scripts/run_v10_benchmark.py`).

### 3.1 Scenario Results & Accuracy Breakdown

| Scenario ID | Threat / Evaluation Vector | Samples | Correct | Accuracy | Expected Verdict |
|---|---|---|---|---|---|
| **SCENARIO-A** | Benign Tool Operations | 100 | 90 | **90.0%** | ALLOW |
| **SCENARIO-B** | Direct Prompt Injection & Goal Hijacking | 50 | 50 | **100.0%** | BLOCK |
| **SCENARIO-C** | Cross-Namespace Access Denial | 50 | 50 | **100.0%** | HTTP 403 FORBIDDEN |
| **SCENARIO-D** | Delegation Capability Escalation Prevention | 50 | 50 | **100.0%** | BLOCK |
| **SCENARIO-E** | High-Frequency Tool Burst Abuse | 50 | 50 | **100.0%** | RISK EVALUATED |
| **SCENARIO-F** | Filesystem Path Traversal Prevention | 50 | 50 | **100.0%** | BLOCK |
| **SCENARIO-G** | Network Egress Exfiltration Restriction | 50 | 50 | **100.0%** | BLOCK |
| **SCENARIO-H** | Secret Exfiltration & Output Redaction | 50 | 50 | **100.0%** | REDACTED |
| **SCENARIO-I** | Webhook HMAC-SHA-256 Replay Attacks | 50 | 50 | **100.0%** | REPLAY REJECTED |
| **SCENARIO-J** | Revoked & Expired Credential Abuse | 50 | 50 | **100.0%** | HTTP 401 UNAUTHORIZED |
| **Total** | **Comprehensive Operational Suite** | **550** | **540** | **98.18%** | Aggregate Accuracy |

### 3.2 Granular Latency Profiling

Latency characteristics differ substantially between full multi-stage interception and isolated fast-path guards. The platform must not be characterized as a blanket "sub-15ms" system; rather, the operational measurements reflect:

#### Full Interception Pipeline (11.17 ms – 16.81 ms median)
Includes canonical request normalization, database policy lookup, static rule evaluation, stateful Bayesian behavioral anomaly detection, and PostgreSQL audit logging:
- **Scenario A (Benign Tool Operations)**: p50 = 11.35 ms, p95 = 15.87 ms, Mean = 13.02 ms
- **Scenario B (Prompt Injection Defense)**: p50 = 11.17 ms, p95 = 13.85 ms, Mean = 11.39 ms
- **Scenario E (Tool Burst Anomaly Analysis)**: p50 = 16.81 ms, p95 = 32.45 ms, Mean = 18.60 ms

#### Fast-Path Security Guards & Authentication Paths (0.00 ms – 1.50 ms)
Targeted boundary enforcement and cryptographic checks:
- **Scenario C (Namespace Boundary Authorization)**: p50 = 0.06 ms, p95 = 0.08 ms
- **Scenario D (Delegation Token Attenuation Verification)**: p50 = 0.00 ms, p95 = 0.00 ms
- **Scenario F (Filesystem Path Traversal Check)**: p50 = 0.49 ms, p95 = 0.76 ms
- **Scenario G (Network Egress Sink Validation)**: p50 = 0.01 ms, p95 = 0.03 ms
- **Scenario H (Execution Output Secret Redaction)**: p50 = 0.01 ms, p95 = 0.01 ms
- **Scenario I (Webhook HMAC-SHA-256 Verification)**: p50 = 0.03 ms, p95 = 0.04 ms
- **Scenario J (API Key Authentication & Revocation Check)**: p50 = 1.48 ms, p95 = 2.45 ms

---

## 4. Reproducibility & Verification Standards

1. **Historical Research Integrity**: The historical Phase 0.7 dataset (`research/datasets/dataset-v1.0.jsonl`, 80 scenarios) and baseline reports (`research/reports/`) remain completely unmodified, intact, and reproducible.
2. **Release Regression Verification**: No regression detected across the verified v0.1-v0.9 regression suite; historical research artifacts preserved.
3. **Operational Manifest**: The v1.0 operational benchmark report (`reports/benchmark_v1.0.json`) is cryptographically fingerprinted in `reports/reproducibility_manifest_v1.0.json` with execution environment details and SHA-256 digest.
