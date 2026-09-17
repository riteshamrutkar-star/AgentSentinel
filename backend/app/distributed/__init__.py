"""
AgentSentinel Phase 0.9: Distributed Control Plane Module.
Provides distributed state abstractions, Redis connectivity, distributed locking,
and idempotency management.
"""

from app.distributed.state import (
    DistributedStateBackend,
    LocalStateBackend,
    RedisStateBackend,
    get_state_backend,
)
from app.distributed.redis import get_redis_client, RedisManager

__all__ = [
    "DistributedStateBackend",
    "LocalStateBackend",
    "RedisStateBackend",
    "get_state_backend",
    "get_redis_client",
    "RedisManager",
]
