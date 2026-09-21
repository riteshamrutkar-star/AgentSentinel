# AgentSentinel v1.0 — Security Precedence & Evaluation Rules

## 1. Decision Pipeline Precedence Order

When an AI agent requests tool execution, the request traverses the security control plane in the following strict order of precedence:

1. **Namespace Authorization (Boundary Check)**:
   - Evaluated before policy or behavioral analysis.
   - If the requesting principal is not authorized for the requested namespace:
     $$\text{Requested Namespace} \notin \text{Authorized Namespaces} \implies \text{HTTP 403 Forbidden}$$
   - Execution halts immediately.

2. **Agent Lifecycle Status Check**:
   - If the agent is marked `REVOKED` or `SUSPENDED` in the registry, execution is immediately denied (`PolicyResult.DENY`).

3. **Multi-Agent Delegation Verification**:
   - If the request is made under a delegation token, the token must be active, unexpired, and possess the requested capability.
   - **Attenuation Invariant**: Child capabilities $\subseteq$ Parent capabilities. A delegating agent cannot grant capabilities it does not own.
   - Any delegation violation results in immediate irrevocable `DENY`.

4. **Static Policy Evaluation (RBAC / ABAC Engine)**:
   - Rules are evaluated in deterministic priority order.
   - **Irrevocable DENY Invariant**: An explicit policy `DENY` is permanent. Neither behavioral anomaly detection nor human approval can overturn a static policy `DENY`.

5. **Behavioral Anomaly Detection (Dynamic Escalation)**:
   - Analyzes recent session history across sequence, burst, transition, and role deviation detectors.
   - **Escalation-Only Invariant**: Behavioral risk can **strengthen** an `ALLOW` verdict into `REQUIRE_APPROVAL` or `DENY`. It can **never weaken** a `DENY` verdict into `ALLOW` or `REQUIRE_APPROVAL`.

6. **Human Approval Lifecycle**:
   - If the final verdict is `REQUIRE_APPROVAL`, an approval request is provisioned in PostgreSQL and the tool execution is paused.
   - A human operator with `OPERATOR` role or higher may approve the request.
   - Approval only transitions an action from `REQUIRE_APPROVAL` to `APPROVED`. It cannot overturn an explicit policy `DENY`.

7. **Authoritative Execution Gateway**:
   - Tool execution must pass through the gateway, which performs 14 pre-execution checks (tool enabled, arguments schema, sandboxing profile, filesystem/network guards, timeout, and output redaction).
