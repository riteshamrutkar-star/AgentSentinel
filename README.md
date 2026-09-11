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
│   │   ├── api/                   # FastAPI controllers (intercept, risk, audit, dashboard)
│   │   ├── audit/                 # Durable audit logging & human approval workflow
│   │   ├── core/                  # Configuration (pydantic-settings), logging, CORS
│   │   ├── db/                    # PostgreSQL 17 SQLAlchemy ORM models, session & CRUD
│   │   ├── evaluation/            # Formal research metrics calculator (Precision, Recall, F1, Latency)
│   │   ├── events/                # Domain models, Pydantic schemas, and event factories
│   │   ├── interceptor/           # Proxy normalizer, schemas, and runtime interceptor
│   │   ├── policy/                # RBAC/ABAC rules and priority evaluation engine
│   │   └── main.py                # FastAPI app factory, CORS, and global exception handler
│   ├── tests/                     # Automated pytest suite (59 passing tests)
│   ├── requirements.txt           # Python dependencies
│   └── Dockerfile                 # Backend container definition
├── dashboard/                     # React + Vite + TypeScript SOC Security Dashboard
│   ├── src/                       # Dashboard UI, KPI cards, Recharts, Risk telemetry drawer
│   ├── package.json               # Frontend dependencies (React 19, Tailwind CSS v4, Lucide)
│   └── vite.config.ts             # Vite configuration with Tailwind plugin
├── scripts/
│   ├── demo_final_evaluation.py   # Phase 10 end-to-end evaluation & demonstration runner
│   └── demo_behavioral_evaluation.py # Phase 0.3 10-scenario research evaluation & metrics benchmark
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

Run the full pytest suite (59 tests covering health, events, policy rules, interceptor, baseline profiling, 5 modular detectors, unified risk engine, fail-closed safety, audit approvals, LangChain runner, database transactions, and REST APIs):

```powershell
# From project root:
backend\venv\Scripts\python.exe -m pytest backend/tests/ -v
```

---

## 🎬 Running System Evaluations & Benchmarks

### 1. Phase 0.3 Advanced Behavioral Research Evaluation
Executes 10 controlled attack and benign scenarios, comparing the Baseline Statistical Detector against the Unified Risk Intelligence Engine with formal research metrics (Precision, Recall, F1, FPR, FNR, Detection Rate, and Latency):

```powershell
backend\venv\Scripts\python.exe scripts/demo_behavioral_evaluation.py
```

### 2. Phase 10 End-to-End System Evaluation
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

## 🔒 Core Security Principles
- **Fail-Closed by Design**: If any detector or database operation encounters an unexpected error during mediation, the action is blocked and execution is refused.
- **Durable Auditability**: 100% of decisions, anomaly scores, multi-detector risk decompositions, and human approvals are permanently stored in PostgreSQL.
- **Zero-Bypass Interception**: Secured tools encapsulate the underlying capability; tool code can never run without prior explicit security authorization.
- **Explainable Decisions**: Every behavioral escalation records clear top risk factors and factual evidence strings visible in the SOC dashboard.
