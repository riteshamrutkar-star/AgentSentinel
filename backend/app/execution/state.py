"""
AgentSentinel Phase 0.5: Execution Lifecycle State Machine.
Defines valid lifecycle states and strictly enforces allowed state transitions.
Rejects invalid jumps (e.g. BLOCKED -> RUNNING or COMPLETED -> RUNNING).
"""

from typing import Dict, Set
from app.core.logger import logger
from app.execution.models import ExecutionState


class ExecutionStateMachine:
    """
    State machine governing an execution context from request to termination.
    Fails closed if any unauthorized state transition is attempted.
    """

    ALLOWED_TRANSITIONS: Dict[ExecutionState, Set[ExecutionState]] = {
        ExecutionState.REQUESTED: {
            ExecutionState.VALIDATED,
            ExecutionState.BLOCKED,
            ExecutionState.PENDING_APPROVAL,
            ExecutionState.CANCELLED,
        },
        ExecutionState.VALIDATED: {
            ExecutionState.RUNNING,
            ExecutionState.PENDING_APPROVAL,
            ExecutionState.BLOCKED,
            ExecutionState.CANCELLED,
        },
        ExecutionState.PENDING_APPROVAL: {
            ExecutionState.APPROVED,
            ExecutionState.BLOCKED,
            ExecutionState.CANCELLED,
        },
        ExecutionState.APPROVED: {
            ExecutionState.RUNNING,
            ExecutionState.BLOCKED,
            ExecutionState.CANCELLED,
        },
        ExecutionState.RUNNING: {
            ExecutionState.COMPLETED,
            ExecutionState.FAILED,
            ExecutionState.TIMEOUT,
            ExecutionState.CANCELLED,
            ExecutionState.BLOCKED,
        },
        ExecutionState.COMPLETED: set(),  # Terminal state
        ExecutionState.FAILED: set(),     # Terminal state
        ExecutionState.BLOCKED: set(),    # Terminal state
        ExecutionState.TIMEOUT: set(),    # Terminal state
        ExecutionState.CANCELLED: set(),  # Terminal state
    }

    @classmethod
    def can_transition(cls, current_state: ExecutionState, new_state: ExecutionState) -> bool:
        """Checks if a transition between two states is valid."""
        allowed = cls.ALLOWED_TRANSITIONS.get(current_state, set())
        return new_state in allowed

    @classmethod
    def transition(cls, current_state: ExecutionState, new_state: ExecutionState) -> ExecutionState:
        """
        Transitions to new_state if valid.
        Raises ValueError if transition is unauthorized.
        """
        if not cls.can_transition(current_state, new_state):
            err = f"INVALID_STATE_TRANSITION: Cannot transition execution from '{current_state.value}' to '{new_state.value}'."
            logger.error(err)
            raise ValueError(err)
        return new_state
