# Changelog - `agentsentinel` SDK

All notable changes to the `agentsentinel` client library are documented in this file.

## [1.0.0] - 2026-09-18
### Added
- Official v1.0.0 stable release of the AgentSentinel Developer SDK.
- Support for `AgentSentinelClient` (synchronous) and `AsyncAgentSentinelClient` (asynchronous).
- Standardized typed exceptions: `SecurityBlockedError`, `ApprovalPendingError`, `RateLimitExceededError`, `ConflictError`, `AuthenticationError`, `AuthorizationError`.
- Durable namespace propagation with per-request overrides.
- Fail-closed runtime safety option (`fail_closed=True`).
- Automatic retry logic with exponential backoff for transient connection errors.
- Support for both standard API Keys (`X-API-Key`) and federated OIDC Bearer tokens (`Authorization: Bearer <jwt>`).
