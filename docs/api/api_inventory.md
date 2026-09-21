# AgentSentinel v1.0 — Standardized API Inventory

## 1. Stable v1 REST API Surface

All public interfaces are versioned under `/api/v1/...` and support standard JSON request/response payloads with unified error structures.

| Endpoint | Method | Authentication | Required Role | Namespace Scoped | Idempotency Supported | Response Model | Error Model |
| :--- | :---: | :--- | :--- | :---: | :---: | :--- | :--- |
| `/health` | `GET` | None | Public | No | No | `HealthResponse` | `HTTPException` |
| `/health/ready` | `GET` | None | Public | No | No | `ReadinessResponse` | `HTTPException` |
| `/api/v1/intercept` | `POST` | API Key / OIDC | Authenticated | Yes | Yes | `InterceptorResponse` | `HTTPException` |
| `/api/v1/intercept/tool-call`| `POST` | API Key / OIDC | Authenticated | Yes | Yes | `InterceptorResponse` | `HTTPException` |
| `/api/v1/policy/rules` | `GET` | API Key / OIDC | VIEWER | Yes | No | `List[PolicyRule]` | `HTTPException` |
| `/api/v1/audit/events` | `GET` | API Key / OIDC | VIEWER | Yes | No | `List[AuditEvent]` | `HTTPException` |
| `/api/v1/audit/events/{id}` | `GET` | API Key / OIDC | VIEWER | Yes | No | `AuditEventDetail` | `HTTPException` |
| `/api/v1/audit/approvals` | `GET` | API Key / OIDC | VIEWER | Yes | No | `List[Approval]` | `HTTPException` |
| `/api/v1/audit/approvals/{id}`| `GET` | API Key / OIDC | VIEWER | Yes | No | `ApprovalDetail` | `HTTPException` |
| `/api/v1/audit/approvals/{id}/approve` | `POST` | API Key / OIDC | OPERATOR | Yes | Yes | `ApprovalActionResponse` | `HTTPException` |
| `/api/v1/audit/approvals/{id}/reject` | `POST` | API Key / OIDC | OPERATOR | Yes | Yes | `ApprovalActionResponse` | `HTTPException` |
| `/api/v1/execution/validate` | `POST` | API Key / OIDC | Authenticated | Yes | No | `ExecutionValidateResponse` | `HTTPException` |
| `/api/v1/execution/submit` | `POST` | API Key / OIDC | Authenticated | Yes | Yes | `ExecutionOutput` | `HTTPException` |
| `/api/v1/execution/run` | `POST` | API Key / OIDC | Authenticated | Yes | Yes | `ExecutionOutput` | `HTTPException` |
| `/api/v1/execution/tools` | `GET` | API Key / OIDC | VIEWER | No | No | `List[ToolResponse]` | `HTTPException` |
| `/api/v1/execution/tools/{id}`| `GET` | API Key / OIDC | VIEWER | No | No | `ToolResponse` | `HTTPException` |
| `/api/v1/execution/tools/{id}/disable` | `POST` | API Key / OIDC | SECURITY_ADMIN | No | Yes | `ToolActionResponse` | `HTTPException` |
| `/api/v1/agents` | `GET` | API Key / OIDC | VIEWER | Yes | No | `List[AgentIdentity]` | `HTTPException` |
| `/api/v1/agents` | `POST` | API Key / OIDC | SECURITY_ADMIN | Yes | Yes | `AgentIdentity` | `HTTPException` |
| `/api/v1/agents/{id}` | `GET` | API Key / OIDC | VIEWER | Yes | No | `AgentIdentity` | `HTTPException` |
| `/api/v1/agents/{id}/revoke` | `POST` | API Key / OIDC | SECURITY_ADMIN | Yes | Yes | `AgentRevokeResponse` | `HTTPException` |
| `/api/v1/alerts` | `GET` | API Key / OIDC | VIEWER | Yes | No | `List[SecurityAlertResponse]` | `HTTPException` |
| `/api/v1/alerts/{id}/action` | `POST` | API Key / OIDC | OPERATOR | Yes | Yes | `SecurityAlertResponse` | `HTTPException` |
| `/api/v1/distributed/status` | `GET` | API Key / OIDC | VIEWER | Yes | No | `DistributedStatusResponse` | `HTTPException` |
| `/api/v1/distributed/webhooks` | `GET` | API Key / OIDC | VIEWER | Yes | No | `List[WebhookDeliveryResponse]` | `HTTPException` |
| `/api/v1/distributed/webhooks/test` | `POST` | API Key / OIDC | OPERATOR | Yes | Yes | `WebhookTestResponse` | `HTTPException` |
| `/api/v1/distributed/metrics` | `GET` | API Key / OIDC | VIEWER | No | No | `BenchmarkMetricsResponse` | `HTTPException` |
| `/api/v1/auth/me` | `GET` | API Key / OIDC | Public/Self | No | No | `IdentityInfoResponse` | `HTTPException` |
