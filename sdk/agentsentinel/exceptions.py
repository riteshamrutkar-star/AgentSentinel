"""
AgentSentinel Developer SDK: Exceptions.
Typed hierarchy of exceptions returned by the AgentSentinel Control Plane.
"""

from typing import Any, Dict, Optional


class AgentSentinelError(Exception):
    """Base exception for all AgentSentinel SDK operations."""
    pass


class SecurityBlockedError(AgentSentinelError):
    """
    Raised when AgentSentinel denies a tool invocation or security evaluation.
    Holds decision reason, security event ID, and threat indicators.
    """

    def __init__(
        self,
        message: str,
        event_id: Optional[str] = None,
        decision_reason: Optional[str] = None,
        verdict: str = "BLOCK",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.event_id = event_id
        self.decision_reason = decision_reason or message
        self.verdict = verdict
        self.details = details or {}


class ApprovalPendingError(AgentSentinelError):
    """Raised when an operation requires asynchronous human approval before proceeding."""

    def __init__(self, message: str, event_id: Optional[str] = None, approval_id: Optional[str] = None):
        super().__init__(message)
        self.event_id = event_id
        self.approval_id = approval_id


class RateLimitExceededError(AgentSentinelError):
    """Raised when API client or agent exceeds assigned sliding-window request quota (HTTP 429)."""
    status_code: int = 429

    def __init__(self, message: str, retry_after_seconds: int = 60, quota_limit: int = 0, status_code: int = 429):
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds
        self.retry_after = retry_after_seconds
        self.quota_limit = quota_limit
        self.status_code = status_code


class AuthenticationError(AgentSentinelError):
    """Raised when API key or bearer token is invalid, expired, or rejected (HTTP 401)."""
    pass


class AuthorizationError(AgentSentinelError):
    """Raised when authenticated identity lacks role or namespace permissions (HTTP 403)."""
    pass


class ConflictError(AgentSentinelError):
    """Raised when an idempotency key is reused with conflicting payload (HTTP 409)."""
    pass


class ConnectionError(AgentSentinelError):
    """Raised when communication with the AgentSentinel Control Plane fails."""
    pass
