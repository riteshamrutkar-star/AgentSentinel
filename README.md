# AgentSentinel v0.1

Runtime Security & Permission Auditing Framework for Tool-Using AI Agents.

---

## 🛡️ What is AgentSentinel?

**AgentSentinel** is a runtime security layer designed to inspect, validate, and audit tool invocations made by Autonomous AI Agents before they are executed. As AI agents gain access to sensitive tools (such as database queries, system commands, HTTP endpoints, or file operations), AgentSentinel acts as a protective proxy or middleware to enforce safety policies, prevent unauthorized actions, and maintain a verifiable audit trail.

---

## 🎯 What the v0.1 Prototype Does

This initial prototype (**v0.1**) establishes the repository skeleton and backend foundation:
- **Modular Project Layout**: Organized directories for `backend`, `agent`, `simulator`, `dashboard`, and `scripts`.
- **FastAPI Core Service**: High-performance asynchronous API backend configured for clean extension.
- **Environment Configuration**: Centralized setting management with environment variable support (`pydantic-settings`).
- **Structured Logging**: Pre-configured standard logging format for tracking events and security operations.
- **Health Verification**: `/health` endpoint providing operational status metrics.
- **Container Readiness**: `Dockerfile` and `docker-compose.yml` for quick containerized deployment.

---

## 📁 Repository Structure

```text
AgentSentinel/
├── backend/               # FastAPI backend security engine
│   ├── app/
│   │   ├── api/           # API routes & endpoint controllers
│   │   │   └── routes.py  # Primary router including /health
│   │   ├── core/          # Core utilities & configuration
│   │   │   ├── config.py  # Environment settings
│   │   │   └── logger.py  # Structured logging configuration
│   │   └── main.py        # FastAPI app initialization & entrypoint
│   ├── Dockerfile         # Docker build file for backend
│   └── requirements.txt   # Python dependencies
├── agent/                 # [Placeholder] AI Agent wrapper / Interceptor SDK
├── simulator/             # [Placeholder] Test attack & simulation scenarios
├── dashboard/             # [Placeholder] UI dashboard for security audit logs
├── scripts/               # [Placeholder] Utility & setup scripts
├── .env.example           # Example environment configuration
├── docker-compose.yml     # Docker Compose orchestration
└── README.md              # Project documentation
```

---

## 🚀 How to Run the Backend Locally

### Option 1: Native Python & Uvicorn

1. **Navigate to the backend directory**:
   ```bash
   cd backend
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Linux/macOS:
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Start the FastAPI backend server**:
   ```bash
   uvicorn app.main:app --reload --port 8000
   ```

5. **Verify the server is running**:
   - Access OpenAPI Docs: [http://localhost:8000/docs](http://localhost:8000/docs)
   - Check Health Endpoint: [http://localhost:8000/health](http://localhost:8000/health)

---

### Option 2: Docker Compose

1. **From the project root, start the container**:
   ```bash
   docker-compose up --build
   ```

2. **Test health response**:
   ```bash
   curl http://localhost:8000/health
   ```

---

## 🔮 What Comes Next (Roadmap)

- **Phase 3: Interception Proxy Engine**: Middleware to parse incoming agent tool call requests (tool name, arguments, agent identity).
- **Phase 4: Policy Enforcement Rules**: Rule engine to evaluate allowed, restricted, or blocked tool calls based on context and role-based permissions.
- **Phase 5: Audit Log & Anomaly Detection**: Persistent logging of all intercepted tool calls with basic anomaly detection.
- **Phase 6: Monitoring Dashboard**: Modern web interface to inspect real-time security events and policy violations.
