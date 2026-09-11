"""
AgentSentinel Phase 0.6: Attack Simulation Context & Safety Boundaries.
Ensures all attack simulations run within strict, non-destructive safety parameters,
with isolated sessions and synthetic target resources.
"""

import uuid
import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AttackSimulationContext(BaseModel):
    """
    Runtime execution context for a simulated attack scenario.
    Provides session isolation, synthetic resource parameters, and safety guarantees.
    """
    simulation_id: str = Field(default_factory=lambda: f"sim_{uuid.uuid4().hex[:8]}")
    session_id: str = Field(default_factory=lambda: f"sess_attack_sim_{uuid.uuid4().hex[:8]}")
    started_at: float = Field(default_factory=time.time)
    safety_mode: bool = True               # Enforces non-destructive synthetic targets
    max_steps: int = 20                    # Upper bound on attack chain length
    timeout_per_step_seconds: float = 10.0 # Timeout per step
    isolation_namespace: str = "sandbox_sim"
    mock_resources: Dict[str, str] = Field(
        default_factory=lambda: {
            "synthetic_shadow_path": "/etc/shadow",
            "synthetic_ssh_path": ".ssh/id_rsa",
            "synthetic_aws_path": ".aws/credentials",
            "synthetic_metadata_url": "http://169.254.169.254/latest/meta-data/iam",
            "synthetic_exfil_url": "https://webhook.site/simulated-sink-001",
            "synthetic_db_table": "production_sensitive_customers",
            "synthetic_traversal_path": "../../Windows/System32/config/SAM",
        }
    )
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def generate_isolated_session(self) -> str:
        """Generates a fresh, isolated session ID for a sub-chain or replay."""
        return f"sess_attack_sim_{uuid.uuid4().hex[:8]}"
