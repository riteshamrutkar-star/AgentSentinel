# AgentSentinel v0.1

**Runtime Security, Policy Enforcement & Permission Control Layer for AI Agents**

AgentSentinel mediates tool invocations executed by autonomous AI agents before execution. It normalizes raw tool calls into structured Security Events, evaluates them against RBAC/ABAC security policies, analyzes behavioral sequences for anomalies, supports human administrator approval workflows, persists durable audit logs in PostgreSQL 17, and provides a real-time Security Operations Center (SOC) dashboard.

---

## 🛡️ Architecture & Multi-Layer Enforcement Flow

Every tool invocation passes through the hardened security and behavioral risk pipeline:

```text
RAW TOOL CALL (from LangChain Agent or SDK)
    ↓
REQUEST NORMALIZATION (ToolCallRequest → SecurityEvent)
    ↓
RBAC / ABAC POLICY ENGINE (ALLOW, BLOCK, REQUIRE_APPROVAL)
    ↓
UNIFIED BEHAVIORAL RISK INTELLIGENCE ENGINE
  ├── Statistical Baseline Detector       (Historical heuristics)
  ├── Sequence Anomaly Detector           (Ordered attack chains)
  ├── Burst & Frequency Detector          (Rapid sub-2s bursts & hammering)
  ├── Tool Transition Matrix Detector     (Pairwise risk transitions)
  └── Role-Capability Mismatch Detector  (Privilege overreach)
    ↓
STRICT PRECEDENCE & RISK ESCALATION
  ├── Policy DENY         → Immutable BLOCK (Never weakened)
  ├── Policy REQUIRE_APPR → REQUIRE_APPROVAL (or BLOCK if Critical)
  └── Policy ALLOW        → Escalate to REQUIRE_APPROVAL (High) or BLOCK (Critical)
    ↓
DURABLE AUDIT PERSISTENCE (PostgreSQL 17 trail & ApprovalModel queue)
    ↓
EXECUTION DISPATCH (Executed ONLY when explicitly permitted)
```

---

## 📁 Repository Structure

```text
AgentSentinel/
├── backend/                        # FastAPI Backend & Security Core
│   ├── app/
│   │   ├── agent/                 # LangChain Agent integration, prompts, secured tools
│   │   ├── anomaly/               # Advanced Behavioral Detection & Risk Engine
│   │   │   ├── baselines.py       # Session & agent baseline profiling engine
│   │   │   ├── config.py          # Centralized weights, thresholds, and transition matrices
│   │   │   ├── engine.py          # UnifiedRiskEngine & multi-signal scoring orchestrator
│   │   │   ├── feature_engine.py  # Rich temporal and behavioral feature extraction
│   │   │   └── detectors/         # Modular detector suite (5 specialized detectors)
│   │   ├── api/                   # FastAPI controllers (intercept, risk, audit, dashboard, multiagent)
│   │   ├── audit/                 # Durable audit logging & human approval workflow
│   │   ├── core/                  # Configuration (pydantic-settings), logging, CORS
│   │   ├── db/                    # PostgreSQL 17 SQLAlchemy ORM models, session & CRUD
│   │   ├── evaluation/            # Formal research metrics calculator (Precision, Recall, F1, Latency)
│   │   ├── events/                # Domain models, Pydantic schemas, and event factories
│   │   ├── interceptor/           # Proxy normalizer, schemas, and runtime interceptor
│   │   ├── multiagent/            # Phase 0.4 Multi-Agent Governance & Identity Engine
│   │   │   ├── adapter.py         # Framework adapter (LangChainMultiAgentAdapter)
│   │   │   ├── config.py          # Multi-agent thresholds, limits, and defaults
│   │   │   ├── delegation.py      # Delegation token lifecycle & scope verification
│   │   │   ├── escalation.py      # Privilege escalation, circularity & depth guards
│   │   │   ├── interceptor.py     # AgentMessageInterceptor (A2A message mediation)
│   │   │   ├── models.py          # Identity, Capability, Trust, Message & Token models
│   │   │   ├── registry.py        # AgentRegistry (in-memory + PostgreSQL persistence)
│   │   │   └── trust.py           # AgentTrustEngine (explainable degradation scoring)
│   │   ├── policy/                # RBAC/ABAC rules and priority evaluation engine
│   │   └── main.py                # FastAPI app factory, CORS, and global exception handler
│   ├── tests/                     # Automated pytest suite (79 passing tests)
│   ├── requirements.txt           # Python dependencies
│   └── Dockerfile                 # Backend container definition
├── dashboard/                     # React + Vite + TypeScript SOC Security Dashboard
│   ├── src/                       # Dashboard UI, KPI cards, Recharts, Multi-Agent Governance
│   ├── package.json               # Frontend dependencies (React 19, Tailwind CSS v4, Lucide)
│   └── vite.config.ts             # Vite configuration with Tailwind plugin
├── scripts/
│   ├── demo_final_evaluation.py   # Phase 10 end-to-end evaluation & demonstration runner
│   ├── demo_behavioral_evaluation.py # Phase 0.3 10-scenario behavioral evaluation benchmark
│   └── demo_multi_agent_evaluation.py # Phase 0.4 12-scenario multi-agent governance benchmark
├── .env.example                   # Environment configuration template
└── final_evaluation_report.md     # Benchmark evaluation report
```

---

## 🚀 Setup & Execution Guide

### 1. Prerequisites
- Python 3.11+ (Python 3.13 supported)
- PostgreSQL 17 running on port `5432`
- Node.js 18+ and npm

### 2. Environment Configuration
Create a `.env` file in the project root or in `backend/`:
```env
APP_NAME=AgentSentinel
APP_VERSION=0.1.0
ENVIRONMENT=development
DEBUG=True
HOST=0.0.0.0
PORT=8000
LOG_LEVEL=INFO

POSTGRES_USER=postgres
POSTGRES_PASSWORD=YOUR_POSTGRES_PASSWORD
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=agentsentinel
DATABASE_URL=postgresql://postgres:YOUR_POSTGRES_PASSWORD@localhost:5432/agentsentinel
```

### 3. Backend Setup & Startup
```powershell
cd backend
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt

# Start FastAPI backend
uvicorn app.main:app --reload --port 8000
```
- OpenAPI Documentation: [http://localhost:8000/docs](http://localhost:8000/docs)
- Health Status: [http://localhost:8000/health](http://localhost:8000/health)

### 4. Frontend Dashboard Startup
```powershell
cd dashboard
npm install
npm run dev
```
Open [http://localhost:5173](http://localhost:5173) in your browser.

---

## 🧪 Running the Automated Test Suite

Run the full pytest suite (79 tests covering health, events, policy rules, interceptor, baseline profiling, 5 modular detectors, unified risk engine, multi-agent identity, dynamic trust, privilege escalation, delegation tokens, circularity, depth limits, fail-closed safety, audit approvals, LangChain runner, database transactions, and REST APIs):

```powershell
# From project root:
backend\venv\Scripts\python.exe -m pytest backend/tests/ -v
```

---

## 🎬 Running System Evaluations & Benchmarks

### 1. Phase 0.4 Multi-Agent Security & Governance Benchmark
Executes 12 controlled multi-agent interaction and attack scenarios, verifying agent identity validation, capability privilege escalation, delegation depth limits, circular delegation loop prevention, token impersonation protection, dynamic trust degradation, and end-to-end multi-agent tool execution provenance:

```powershell
backend\venv\Scripts\python.exe scripts/demo_multi_agent_evaluation.py
```

| Metric | Measured Benchmark Value | Target / Security Guarantee |
| :--- | :--- | :--- |
| **Evaluated Scenarios** | **12 / 12** | 100% test coverage |
| **Precision** | **1.0000** | Zero false accusations |
| **Recall (Detection Rate)** | **1.0000** | Zero missed multi-agent attacks |
| **F1 Score** | **1.0000** | Harmonic balance |
| **False Positive Rate (FPR)** | **0.0000** | Zero valid delegations blocked |
| **False Negative Rate (FNR)** | **0.0000** | Zero compromised delegations allowed |
| **Average Processing Latency** | **21.27 ms** | Low sub-50ms overhead |

### 2. Phase 0.3 Advanced Behavioral Research Evaluation
Executes 10 controlled attack and benign scenarios, comparing the Baseline Statistical Detector against the Unified Risk Intelligence Engine with formal research metrics (Precision, Recall, F1, FPR, FNR, Detection Rate, and Latency):

```powershell
backend\venv\Scripts\python.exe scripts/demo_behavioral_evaluation.py
```

### 3. Phase 10 End-to-End System Evaluation
Runs the full 5-scenario pipeline (benign search, workspace read, credential exfiltration block, database drop approval flow, and behavioral sequence anomaly) and generates [`final_evaluation_report.md`](file:///c:/Users/rites/OneDrive/Desktop/AgentSentinel/AgentSentinel/final_evaluation_report.md):

```powershell
backend\venv\Scripts\python.exe scripts/demo_final_evaluation.py
```

---

## 🧠 Behavioral Risk Intelligence Engine (Phase 0.3)

AgentSentinel Phase 0.3 replaces single-heuristic scoring with an explainable multi-signal behavioral risk engine:

### Modular Detectors Suite
1. **Statistical Baseline Detector (`w = 0.15`)**: Heuristic baseline analyzing sensitive tool volume, failure ratios, and deviation from session norm.
2. **Sequence Anomaly Detector (`w = 0.30`)**: Identifies ordered reconnaissance, privilege escalation, and exfiltration threat chains (e.g., `PROBE_TO_EXFILTRATE`, `RECON_BEFORE_DESTRUCTION`).
3. **Burst & Frequency Detector (`w = 0.15`)**: Measures invocation velocity, flagging rapid sub-2-second bursts, 60s volume spikes, and consecutive endpoint hammering.
4. **Tool Transition Matrix Detector (`w = 0.20`)**: Computes directed Markov transition risk probabilities between adjacent tool calls.
5. **Role-Capability Mismatch Detector (`w = 0.20`)**: Detects tools and action types violating the agent's defined functional scope.

### Unified Risk Scoring & Peak Severity Guarantee
The composite score is calculated via normalized weighted sum, combined with a peak-threat floor guarantee so that critical single-detector detections are never diluted:
$$\text{Raw Score} = \max\left(\sum w_i \cdot s_i, \; \max(s_i) \times 0.90 \text{ when } \max(s_i) \ge 0.85\right)$$
Clamped strictly to $[0.0, 1.0]$.

### Deterministic Policy Precedence Invariants
- **Policy DENY** is absolute and immutable: behavioral intelligence can never override an explicit block.
- **Policy REQUIRE_APPROVAL** is preserved, escalating to **BLOCK** if risk is `CRITICAL` ($\ge 0.85$).
- **Policy ALLOW** escalates to **REQUIRE_APPROVAL** if risk is `HIGH` ($\ge 0.65$), or **BLOCK** if risk is `CRITICAL` ($\ge 0.85$).

---

## 🤝 Multi-Agent Security & Agent-to-Agent Governance (Phase 0.4)

AgentSentinel Phase 0.4 expands security controls from individual agent-to-tool interactions into distributed multi-agent workflows, delegation structures, agent identities, trust degradation, and agent-to-agent communication mediation.

### Core Multi-Agent Governance Pillars

```text
COORDINATOR AGENT (Origin)
    │
    │ 1. Intercept A2A Delegation Message
    ▼
AGENT MESSAGE INTERCEPTOR
  ├── 1. Verify Sender & Recipient Identities (Fail-closed on unknown or revoked)
  ├── 2. Circular Delegation Guard (Prohibit A → B → ... → A loops)
  ├── 3. Delegation Depth Guard (Enforce MAX_DELEGATION_DEPTH ≤ 3)
  ├── 4. Privilege Escalation Detector (Verify Delegated ⊆ Delegator Authorized)
  └── 5. Dynamic Agent Trust Engine (Evaluate behavioral score & degradation)
    │
    │ [ALLOW] Issue Cryptographic Delegation Context
    ▼
WORKER AGENT (Target)
    │
    │ 2. Execute Delegated Tool (e.g. google_search) with Delegation ID
    ▼
RUNTIME INTERCEPTOR & PROXY
  ├── Verify Delegation Token Authenticity & Target Binding
  ├── Validate Tool falls strictly within Delegated Capability Scope
  ├── Attach Full Multi-Agent Provenance Metadata Chain to Event
  └── Proceed through Policy Engine & Behavioral Risk Engine
    │
    ▼
POSTGRESQL 17 AUDIT TRAIL & SOC DASHBOARD VISUALIZATION
```

### Granular Capability Model
Agents are strictly bound to explicit capability grants:
- `SEARCH`: Web and knowledge base querying (`google_search`).
- `FILE_READ`: Reading workspace files (`read_workspace_file`).
- `FILE_WRITE`: Writing or modifying workspace files (`write_workspace_file`).
- `DATABASE_READ`: Querying database schemas and tables.
- `DATABASE_WRITE`: Destructive database operations (`drop_database_table`).
- `PROCESS_EXECUTION`: Running local or external system processes.
- `CREDENTIAL_ACCESS`: Accessing API keys, secrets, or SSH keys (`read_system_file`).
- `DELEGATION`: Delegating sub-tasks to other registered agents.

### Formal Security Invariants
1. **Privilege Escalation Invariant**: An agent can *never* delegate capabilities it does not possess ($\text{Delegated} \subseteq \text{Delegator Authorized}$). Attempted overreach results in immediate `BLOCK` and trust degradation.
2. **Bounded Delegation Depth**: Delegation chains cannot exceed $\text{MAX\_DELEGATION\_DEPTH} = 3$. Deeper chains are unconditionally blocked.
3. **Circular Delegation Prevention**: Circular delegation loops ($A \to B \to A$) are detected via provenance chain inspection and blocked.
4. **Fail-Closed Identity Validation**: Unregistered shadow agents or revoked compromised agents are blocked immediately.
5. **Explainable Dynamic Trust Engine**: Trust scores ($0.0 \le \text{trust} \le 1.0$) degrade deterministically upon repeated violations, sensitive operations, or escalation attempts, dynamically demoting agents to `UNTRUSTED`.

---

## 🔒 Secure Execution, Sandboxing & Tool Governance (Phase 0.5)

AgentSentinel Phase 0.5 establishes a mandatory, fail-closed runtime execution boundary between authorization and actual tool dispatch:

$$\text{Identity} \to \text{Trust} \to \text{Delegation} \to \text{Policy} \to \text{Behavior} \to \text{Tool Registry} \to \mathbf{Secure Execution Gateway} \to \mathbf{Sandbox Isolation} \to \mathbf{Output Security} \to \mathbf{Durable Audit}$$

No tool, script, or external process can execute without passing all 14 gates of the `SecureExecutionGateway`.

```text
========================================================================================
                         SECURE EXECUTION GATEWAY PIPELINE
========================================================================================
Tool Invocation Request
    │
    ▼
[Gate 1]  Authoritative Tool Registry Lookup & Enabled Status Check
    │
[Gate 2]  Executing Agent Identity Verification & Active Status Check
    │
[Gate 3]  Agent Capability Containment (Agent Capabilities ⊇ Tool Required Capability)
    │
[Gate 4]  Delegation Token Scope, Target Binding & Expiration Validation
    │
[Gate 5]  Policy Verdict Enforcement (Preserve explicit BLOCK / DENY)
    │
[Gate 6]  Approval Scope & Agent/Tool Binding Verification (PostgreSQL backed)
    │
[Gate 7]  Sandbox Profile Resolution (STRICT, STANDARD, RESEARCH, DEVELOPER, PRIVILEGED)
    │
[Gate 8]  Filesystem Sandbox Guard (Path canonicalization, traversal blocking, secret files)
    │
[Gate 9]  Network Egress Guard (Raw IP literals, cloud metadata 169.254.169.254, exfiltration sinks)
    │
[Gate 10] Process Execution Guard (Executable allowlisting, injection tokens, shell=False)
    │
[Gate 11] Sandbox Backend Selection & Isolation (Guarded In-Process or Hardened Docker)
    │
[Gate 12] Sandboxed Execution with Thread/Container Timeout Bounding
    │
[Gate 13] Output Security & Secret Redaction (API keys, tokens redacted; private keys hard-blocked)
    │
[Gate 14] Durable Execution Audit Trail (PostgreSQL executions table record)
    │
    ▼
Sanitized & Approved Execution Output Returned to Caller
```

### Predefined Sandbox Profiles
| Profile | Mode | Network | Process Exec | Memory | Timeout | Description |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`STRICT`** | Zero-trust | Disabled | Disabled | 128 MB | 5.0 s | Zero egress, read-only workspace, no subprocesses. |
| **`STANDARD`** | Balanced | Disabled | Disabled | 256 MB | 10.0 s | Workspace read/write, no external networking or execution. |
| **`RESEARCH`** | Web research | Allowed | Disabled | 256 MB | 15.0 s | Authorized domain allowlist for search and academic sources. |
| **`DEVELOPER`** | Engineering | Allowed | Allowed | 512 MB | 30.0 s | Allowed toolchain executables (python, git, node, npm). |
| **`PRIVILEGED`** | Admin only | Allowed | Allowed | 1024 MB | 60.0 s | Approval-gated database and administrative operations. |

### Secret Protection Layer
- **Automated Masking**: Sensitive tokens matching regular expressions (`GITHUB_TOKEN`, `OPENAI_API_KEY`, `JWT_TOKEN`, `BEARER_TOKEN`, `PASSWORD_ASSIGNMENT`) are redacted into `[REDACTED_<TYPE>]` before audit persistence or caller return.
- **Critical Exfiltration Hard Block**: Outputs containing unencrypted private keys (`PRIVATE_KEY`), root AWS credentials (`AWS_ACCESS_KEY`), or direct database connection strings (`DB_CONNECTION_STRING`) are unconditionally hard-blocked.

---

## 📊 Empirical Benchmark Evaluation Summary

All benchmarks run live against the PostgreSQL 17 database and FastAPI control plane with zero mock or synthetic metrics:

| Benchmark Phase | Test Focus | Scenarios | Accuracy | Precision | Recall | FPR | FNR | Avg Latency |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Phase 10** | End-to-End Control Plane | 5 | 100.0% | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 46.07 ms |
| **Phase 0.3** | Behavioral Risk Intelligence | 10 | 90.0% | 1.0000 | 0.8750 | 0.0000 | 0.1250 | 28.42 ms |
| **Phase 0.4** | Multi-Agent Governance | 12 | 100.0% | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 29.86 ms |
| **Phase 0.5** | Secure Execution Gateway | 20 | 100.0% | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 3.89 ms |

---

## 🔒 Core Security Principles
- **Fail-Closed by Design**: If any detector, validator, sandbox, or database operation encounters an unexpected error during mediation, the action is blocked and execution is refused.
- **Durable Auditability**: 100% of decisions, anomaly scores, multi-detector risk decompositions, delegation tokens, executions, and human approvals are permanently stored in PostgreSQL.
- **Zero-Bypass Interception**: Secured tools encapsulate the underlying capability; tool code can never run without prior explicit security authorization and gateway execution.
- **Mandatory Execution Boundary**: Authorization is enforced physically via filesystem path canonicalization, network destination filtering, and process allowlists.
- **End-to-End Multi-Agent Provenance**: Every delegated tool execution preserves the complete origin-to-execution delegation chain in durable audit metadata.
- **Explainable Decisions**: Every behavioral escalation and delegation decision records clear top risk factors and factual evidence strings visible in the SOC dashboard.

