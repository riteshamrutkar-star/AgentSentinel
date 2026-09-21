"""
AgentSentinel Developer SDK.
Official lightweight client for AI agent tool call interception and security governance.
"""

from .client import (
    AgentSentinelClient,
    AsyncAgentSentinelClient,
)
from .exceptions import (
    AgentSentinelError,
    AuthenticationError,
    AuthorizationError,
    ApprovalPendingError,
    ConflictError,
    ConnectionError,
    RateLimitExceededError,
    SecurityBlockedError,
)

__version__ = "1.0.0"

__all__ = [
    "__version__",
    "AgentSentinelClient",
    "AsyncAgentSentinelClient",
    "AgentSentinelError",
    "AuthenticationError",
    "AuthorizationError",
    "ApprovalPendingError",
    "ConflictError",
    "ConnectionError",
    "RateLimitExceededError",
    "SecurityBlockedError",
]
