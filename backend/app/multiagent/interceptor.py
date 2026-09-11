"""
Agent Message & Delegation Interceptor for AgentSentinel Phase 0.4.
Provides a security gateway for agent-to-agent communication, enforcing identity verification,
trust evaluation, capability boundaries, depth limits, and circularity checks before issuing delegation authority.
"""

import time
import uuid
from typing import Optional
from sqlalchemy.orm import Session

from app.audit.service import record_audit_entry
from app.core.logger import logger
from app.events.factory import create_security_event, enrich_event_security, apply_decision
from app.events.schema import ActionType, PolicyResult, SensitivityLevel
from app.multiagent.config import multiagent_config
from app.multiagent.delegation import DelegationManager, default_delegation_manager
from app.multiagent.escalation import PrivilegeEscalationDetector, default_escalation_detector
from app.multiagent.models import AgentCapability, AgentMessage, DelegationDecision, TrustLevel
from app.multiagent.registry import AgentRegistry, default_agent_registry
from app.multiagent.trust import AgentTrustEngine, default_trust_engine


class AgentMessageInterceptor:
    """
    Runtime security gateway intercepting agent-to-agent messages and delegation requests.
    Validates sender and recipient identities, checks for privilege escalation, circular chains,
    and depth violations, and generates auditable security events in PostgreSQL.
    """

    def __init__(
        self,
        registry: Optional[AgentRegistry] = None,
        trust_engine: Optional[AgentTrustEngine] = None,
        escalation_detector: Optional[PrivilegeEscalationDetector] = None,
        delegation_manager: Optional[DelegationManager] = None,
    ):
        self.registry = registry or default_agent_registry
        self.trust_engine = trust_engine or default_trust_engine
        self.escalation_detector = escalation_detector or default_escalation_detector
        self.delegation_manager = delegation_manager or default_delegation_manager

    def intercept_message(
        self,
        message: AgentMessage,
        db: Optional[Session] = None,
    ) -> DelegationDecision:
        """
        Mediates an agent-to-agent communication or delegation request.
        Fails closed on any validation failure, invariant violation, or unexpected error.
        """
        start_time = time.perf_counter()

        try:
            # 1. Validate Sender Identity
            sender_valid, sender_err = self.registry.validate_agent(message.sender_agent_id, db)
            if not sender_valid:
                return self._create_block_decision(
                    message=message,
                    reason=f"SENDER_VALIDATION_FAILED: {sender_err}",
                    escalation_detected=False,
                    trust_score=0.0,
                    risk_score=0.95,
                    start_time=start_time,
                    db=db,
                )

            # 2. Validate Recipient Identity
            recipient_valid, recipient_err = self.registry.validate_agent(message.recipient_agent_id, db)
            if not recipient_valid:
                return self._create_block_decision(
                    message=message,
                    reason=f"RECIPIENT_VALIDATION_FAILED: {recipient_err}",
                    escalation_detected=False,
                    trust_score=0.50,
                    risk_score=0.95,
                    start_time=start_time,
                    db=db,
                )

            sender = self.registry.get_agent(message.sender_agent_id, db)
            recipient = self.registry.get_agent(message.recipient_agent_id, db)

            # 3. Check Circular Delegation Loop
            provenance = list(message.provenance) if message.provenance else [message.sender_agent_id]
            is_circular, circular_msg = self.escalation_detector.check_circular_delegation(
                target_agent_id=message.recipient_agent_id,
                provenance_chain=provenance,
            )
            if is_circular:
                return self._create_block_decision(
                    message=message,
                    reason=f"CIRCULAR_DELEGATION_PROHIBITED: {circular_msg}",
                    escalation_detected=True,
                    trust_score=sender.trust_score,
                    risk_score=0.90,
                    start_time=start_time,
                    penalties=["circular_delegation"],
                    db=db,
                )

            # 4. Check Delegation Depth Limit
            current_depth = len(provenance)
            depth_exceeded, depth_msg = self.escalation_detector.check_delegation_depth(current_depth)
            if depth_exceeded:
                return self._create_block_decision(
                    message=message,
                    reason=f"DELEGATION_DEPTH_LIMIT_EXCEEDED: {depth_msg}",
                    escalation_detected=True,
                    trust_score=sender.trust_score,
                    risk_score=0.88,
                    start_time=start_time,
                    penalties=["depth_exceeded"],
                    db=db,
                )

            # 5. Check Privilege Escalation Invariant (Delegated <= Delegator)
            is_escalation, esc_msg, unauthorized_caps = self.escalation_detector.check_capability_escalation(
                delegator=sender,
                requested_capabilities=message.requested_capabilities,
            )
            if is_escalation:
                return self._create_block_decision(
                    message=message,
                    reason=f"PRIVILEGE_ESCALATION_BLOCKED: {esc_msg}",
                    escalation_detected=True,
                    escalation_details=f"Unauthorized capabilities: {[c.value for c in unauthorized_caps]}",
                    trust_score=sender.trust_score,
                    risk_score=0.92,
                    start_time=start_time,
                    penalties=["privilege_escalation"],
                    db=db,
                )

            # 6. Evaluate Sender and Recipient Trust
            sender_trust = self.trust_engine.evaluate_agent_trust(message.sender_agent_id, db)
            recipient_trust = self.trust_engine.evaluate_agent_trust(message.recipient_agent_id, db)

            # Untrusted sender attempting to delegate sensitive actions is blocked
            if sender_trust.trust_level == TrustLevel.UNTRUSTED:
                return self._create_block_decision(
                    message=message,
                    reason=f"POLICY_BLOCK: Untrusted agent '{message.sender_agent_id}' is prohibited from delegating tasks.",
                    escalation_detected=False,
                    trust_score=sender_trust.trust_score,
                    risk_score=0.95,
                    start_time=start_time,
                    db=db,
                )

            # 7. Check for Sensitive Capabilities Requiring Human Approval
            sensitive_caps = {
                AgentCapability.DATABASE_WRITE,
                AgentCapability.PROCESS_EXECUTION,
                AgentCapability.CREDENTIAL_ACCESS,
            }
            requires_approval = any(c in sensitive_caps for c in message.requested_capabilities)
            # High trust agents can delegate with lower friction, but destructive DB or credential access always requires approval
            if requires_approval and sender_trust.trust_level not in (TrustLevel.PRIVILEGED,):
                latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
                reason = (
                    f"REQUIRE_APPROVAL: Delegated capability {[c.value for c in message.requested_capabilities]} "
                    f"involves high-risk access requiring administrator sign-off."
                )
                self._record_interception_event(
                    message=message,
                    decision="REQUIRE_APPROVAL",
                    reason=reason,
                    latency_ms=latency_ms,
                    trust_score=sender_trust.trust_score,
                    db=db,
                )
                return DelegationDecision(
                    delegation_id=None,
                    decision="REQUIRE_APPROVAL",
                    reason=reason,
                    escalation_detected=False,
                    trust_score=sender_trust.trust_score,
                    risk_score=0.65,
                    execution_allowed=False,
                    latency_ms=latency_ms,
                )

            # 8. All Checks Passed -> Issue Authorized Delegation Token
            new_chain = provenance + [message.recipient_agent_id]
            delegation = self.delegation_manager.issue_delegation(
                source_agent_id=message.sender_agent_id,
                target_agent_id=message.recipient_agent_id,
                session_id=message.session_id,
                delegated_capabilities=message.requested_capabilities,
                delegation_depth=current_depth,
                parent_delegation_id=message.parent_message_id,
                provenance_chain=new_chain,
                metadata=message.payload_metadata,
                db=db,
            )

            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            reason = (
                f"ALLOW: Delegation from '{message.sender_agent_id}' to '{message.recipient_agent_id}' "
                f"authorized for capabilities {[c.value for c in message.requested_capabilities]}."
            )

            self._record_interception_event(
                message=message,
                decision="ALLOW",
                reason=reason,
                latency_ms=latency_ms,
                trust_score=sender_trust.trust_score,
                delegation_id=delegation.delegation_id,
                db=db,
            )

            return DelegationDecision(
                delegation_id=delegation.delegation_id,
                decision="ALLOW",
                reason=reason,
                escalation_detected=False,
                trust_score=sender_trust.trust_score,
                risk_score=0.10,
                execution_allowed=True,
                latency_ms=latency_ms,
            )

        except Exception as e:
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.error(f"Multi-agent message interception failed: {e}", exc_info=True)
            return DelegationDecision(
                delegation_id=None,
                decision="BLOCK",
                reason=f"SECURITY_ERROR: Message interception failed closed due to error: {str(e)}",
                escalation_detected=False,
                trust_score=0.0,
                risk_score=1.0,
                execution_allowed=False,
                latency_ms=latency_ms,
            )

    def _create_block_decision(
        self,
        message: AgentMessage,
        reason: str,
        escalation_detected: bool,
        trust_score: float,
        risk_score: float,
        start_time: float,
        escalation_details: Optional[str] = None,
        penalties: Optional[list] = None,
        db: Optional[Session] = None,
    ) -> DelegationDecision:
        """Helper to record blocked delegation and return structured decision."""
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # Apply trust degradation if penalties specified
        if penalties and db:
            try:
                self.trust_engine.evaluate_agent_trust(
                    agent_id=message.sender_agent_id,
                    db=db,
                    context_penalties=penalties,
                )
            except Exception:
                pass

        self._record_interception_event(
            message=message,
            decision="BLOCK",
            reason=reason,
            latency_ms=latency_ms,
            trust_score=trust_score,
            db=db,
        )

        return DelegationDecision(
            delegation_id=None,
            decision="BLOCK",
            reason=reason,
            escalation_detected=escalation_detected,
            escalation_details=escalation_details,
            trust_score=trust_score,
            risk_score=risk_score,
            execution_allowed=False,
            latency_ms=latency_ms,
        )

    def _record_interception_event(
        self,
        message: AgentMessage,
        decision: str,
        reason: str,
        latency_ms: float,
        trust_score: float,
        delegation_id: Optional[str] = None,
        db: Optional[Session] = None,
    ):
        """Records an agent-to-agent interception event in PostgreSQL."""
        if not db:
            return

        try:
            sec_event = create_security_event(
                session_id=message.session_id,
                agent_id=message.sender_agent_id,
                user_id=f"a2a_{message.sender_agent_id}",
                tool_name="delegate_task",
                arguments_payload={
                    "target_agent_id": message.recipient_agent_id,
                    "requested_action": message.requested_action,
                    "capabilities": [c.value for c in message.requested_capabilities],
                },
                role="agent_coordinator",
                framework_name="MultiAgentSentinel",
                target_resource=message.recipient_agent_id,
                action_type=ActionType.NETWORK,
                task_summary=message.requested_action,
            )

            policy_res = (
                PolicyResult.ALLOW if decision == "ALLOW"
                else PolicyResult.REQUIRE_APPROVAL if decision == "REQUIRE_APPROVAL"
                else PolicyResult.DENY
            )
            apply_decision(sec_event, policy_result=policy_res, reason=reason)
            sec_event.execution_context.latency_ms = latency_ms

            # Attach multi-agent provenance context into metadata
            sec_event.audit_context.metadata["multi_agent"] = {
                "sender_agent_id": message.sender_agent_id,
                "recipient_agent_id": message.recipient_agent_id,
                "delegation_id": delegation_id,
                "requested_capabilities": [c.value for c in message.requested_capabilities],
                "trust_score": trust_score,
                "provenance_chain": message.provenance,
                "is_a2a_message": True,
            }

            record_audit_entry(db, sec_event)
        except Exception as e:
            logger.warning(f"Failed to record multi-agent audit event in PostgreSQL: {e}")


# Global default AgentMessageInterceptor singleton
default_message_interceptor = AgentMessageInterceptor()
