# AgentSentinel v0.1

**Runtime Security, Policy Enforcement & Permission Control Layer for AI Agents**

AgentSentinel mediates tool invocations executed by autonomous AI agents before execution. It normalizes raw tool calls into structured Security Events, evaluates them against RBAC/ABAC security policies, analyzes behavioral sequences for anomalies, supports human administrator approval workflows, persists durable audit logs in PostgreSQL 17, and provides a real-time Security Operations Center (SOC) dashboard.

---

## 🛡️ Architecture & Enforcement Flow

Every tool invocation passes through the hardened security pipeline:

```text
RAW TOOL CALL (from LangChain Agent or SDK)
    ↓
REQUEST NORMALIZATION (ToolCallRequest → SecurityEvent)
    ↓
RBAC / ABAC POLICY ENGINE (ALLOW, BLOCK, REQUIRE_APPROVAL)
    ↓
BEHAVIORAL ANOMALY DETECTOR (Feature extraction, transition scoring, risk escalation)
    ↓
SECURITY DECISION VERDICT (Deterministic fail-closed control)
    ↓
AUDIT PERSISTENCE (PostgreSQL 17 durable trail & ApprovalModel queue)
    ↓
EXECUTION (Executed ONLY when explicitly permitted)
```

---

## 📁 Repository Structure

```text
AgentSentinel/
├── backend/                        # FastAPI Backend & Security Core
│   ├── app/
│   │   ├── agent/                 # LangChain Agent integration, prompts, secured tools
│   │   ├── anomaly/               # Behavioral feature extraction & anomaly detector
│   │   ├── api/                   # FastAPI route controllers (intercept, audit, dashboard, evaluation)
│   │   ├── audit/                 # Durable audit logging & human approval workflow
│   │   ├── core/                  # Configuration (pydantic-settings), logging, CORS
│   │   ├── db/                    # PostgreSQL 17 SQLAlchemy ORM models, session & CRUD
│   │   ├── evaluation/            # Evaluation metrics and benchmark report generator
│   │   ├── events/                # Domain models, Pydantic schemas, and event factories
│   │   ├── interceptor/           # Proxy normalizer, schemas, and runtime interceptor
│   │   ├── policy/                # RBAC/ABAC rules and priority evaluation engine
│   │   └── main.py                # FastAPI app factory, CORS, and global exception handler
│   ├── tests/                     # Comprehensive automated pytest suite (39 tests)
│   ├── requirements.txt           # Python dependencies
│   └── Dockerfile                 # Backend container definition
├── dashboard/                     # React + Vite + TypeScript SOC Security Dashboard
│   ├── src/                       # Dashboard UI, KPI cards, Recharts, approval drawers
│   ├── package.json               # Frontend dependencies (React 19, Tailwind CSS v4, Lucide)
│   └── vite.config.ts             # Vite configuration with Tailwind plugin
├── scripts/
│   └── demo_final_evaluation.py   # Phase 10 end-to-end evaluation & demonstration runner
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

Run the full pytest suite (39 tests covering health, events, policy rules, interceptor, anomaly detection, audit approvals, LangChain runner, database transactions, and API endpoints):

```powershell
# From project root:
backend\venv\Scripts\python.exe -m pytest backend/tests/ -v
```

---

## 🎬 Running the Final Evaluation & Demonstration

To execute the end-to-end evaluation suite across all 5 benchmark scenarios (benign search, workspace read, credential exfiltration block, database drop approval flow, and behavioral sequence anomaly):

```powershell
backend\venv\Scripts\python.exe scripts/demo_final_evaluation.py
```
This will run the scenarios, print the live execution metrics, and generate [`final_evaluation_report.md`](file:///c:/Users/rites/OneDrive/Desktop/AgentSentinel/AgentSentinel/final_evaluation_report.md).

---

## 🔒 Security Principles
- **Fail-Closed by Design**: If any component encounters an unexpected error during mediation, the action is blocked and execution is refused.
- **Durable Auditability**: 100% of decisions, anomaly scores, and human approvals are permanently stored in PostgreSQL.
- **Zero-Bypass Interception**: Secured tools encapsulate the underlying capability; tool code can never run without prior explicit security authorization.
