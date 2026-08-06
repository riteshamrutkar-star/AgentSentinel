import re
from typing import List, Optional
from app.events.factory import apply_decision, enrich_event_security
from app.events.model import SecurityEvent
from app.events.schema import ApprovalStatus, PolicyResult, SensitivityLevel
from app.policy.rules import get_default_policy_rules
from app.policy.schemas import PolicyEvaluationResult, PolicyRule, RuleEffect

class PolicyEngine:
    """
    RBAC / ABAC / Security Policy Engine for AgentSentinel v0.1.
    Evaluates intercepted tool call security events against explicit, priority-ordered policy rules.
    """

    def __init__(self, custom_rules: Optional[List[PolicyRule]] = None):
        rules_list = custom_rules or get_default_policy_rules()
        # Sort rules by priority ascending (lower number = higher precedence)
        self.rules: List[PolicyRule] = sorted(rules_list, key=lambda r: r.priority)

    def _matches_pattern(self, pattern: str, value: str) -> bool:
        """Helper to match wildcard or pipe-delimited pattern strings."""
        if not pattern or pattern == "*":
            return True
        if not value:
            return False

        # Split pipe-delimited patterns (e.g. "read_file|write_file|list_dir")
        sub_patterns = pattern.split("|")
        val_lower = value.lower().strip()

        for sub in sub_patterns:
            sub = sub.strip().lower()
            if sub == "*":
                return True
            # Simple wildcard conversion (* -> .*)
            regex_str = "^" + re.escape(sub).replace(r"\*", ".*") + "$"
            if re.search(regex_str, val_lower):
                return True

        return False

    def _matches_resource_pattern(self, pattern: str, target_resource: str, arguments_payload: dict) -> bool:
        """Helper to check target resource string or arguments dictionary against resource patterns."""
        if not pattern or pattern == "*":
            return True

        args_str = str(arguments_payload).lower()
        res_str = target_resource.lower()

        sub_patterns = pattern.split("|")
        for sub in sub_patterns:
            sub = sub.strip().lower()
            if not sub:
                continue
            # Remove glob wildcards for simple substring check if regex special
            clean_sub = sub.replace("*", "").strip()
            if clean_sub and (clean_sub in res_str or clean_sub in args_str):
                return True

        return False

    def evaluate(self, security_event: SecurityEvent) -> PolicyEvaluationResult:
        """
        Evaluates a normalized SecurityEvent against registered policy rules in priority order.
        Returns a structured PolicyEvaluationResult and updates the event's decision context.
        """
        role = security_event.identity.role
        tool_name = security_event.tool_action.tool_name
        action_type = security_event.tool_action.action_type.value if hasattr(security_event.tool_action.action_type, 'value') else str(security_event.tool_action.action_type)
        target_resource = security_event.tool_action.target_resource
        arguments = security_event.tool_action.arguments_payload

        matched_rule: Optional[PolicyRule] = None

        for rule in self.rules:
            # Check Role match
            if not self._matches_pattern(rule.role, role):
                continue
            # Check Tool Name match
            if not self._matches_pattern(rule.tool_name, tool_name):
                continue
            # Check Action Type match
            if not self._matches_pattern(rule.action_type, action_type):
                continue
            # Check Resource Pattern match
            if not self._matches_resource_pattern(rule.resource_pattern, target_resource, arguments):
                continue

            # Found matching rule!
            matched_rule = rule
            break

        # If no rule matched, use safe default
        if not matched_rule:
            matched_rule = PolicyRule(
                rule_id="SEC_FALLBACK_ALLOW",
                rule_name="Fallback Standard Permission",
                rule_type="SECURITY",
                effect=RuleEffect.ALLOW,
                priority=9999,
                description="Default fallback permission when no explicit policy rule triggers.",
            )

        # Process verdict based on matched rule effect
        if matched_rule.effect == RuleEffect.BLOCK:
            verdict = "BLOCK"
            policy_res = PolicyResult.DENY
            exec_allowed = False
            approval_req = False
            risk_level = "CRITICAL"
            reason = f"BLOCKED by Policy [{matched_rule.rule_id}]: {matched_rule.description}"
            
            enrich_event_security(
                security_event,
                sensitivity_level=SensitivityLevel.CRITICAL,
                policy_tags=["policy_block", matched_rule.rule_id.lower()],
                risk_indicators=[matched_rule.rule_id],
                anomaly_score=0.90,
                threat_flags=["POLICY_VIOLATION_BLOCKED"],
            )
            apply_decision(
                security_event,
                policy_result=policy_res,
                reason=reason,
            )

        elif matched_rule.effect == RuleEffect.REQUIRE_APPROVAL:
            verdict = "REQUIRE_APPROVAL"
            policy_res = PolicyResult.REQUIRE_APPROVAL
            exec_allowed = False
            approval_req = True
            risk_level = "HIGH"
            reason = f"REQUIRE_APPROVAL by Policy [{matched_rule.rule_id}]: {matched_rule.description}"
            
            enrich_event_security(
                security_event,
                sensitivity_level=SensitivityLevel.HIGH,
                policy_tags=["policy_approval_required", matched_rule.rule_id.lower()],
                risk_indicators=[matched_rule.rule_id],
                anomaly_score=0.75,
                threat_flags=["REQUIRES_HUMAN_APPROVAL"],
            )
            apply_decision(
                security_event,
                policy_result=policy_res,
                reason=reason,
                approval_required=True,
                approval_status=ApprovalStatus.PENDING,
            )

        else: # ALLOW
            verdict = "ALLOW"
            policy_res = PolicyResult.ALLOW
            exec_allowed = True
            approval_req = False
            risk_level = "LOW"
            reason = f"ALLOWED by Policy [{matched_rule.rule_id}]: {matched_rule.rule_name}"
            
            enrich_event_security(
                security_event,
                sensitivity_level=SensitivityLevel.LOW,
                policy_tags=["policy_allowed", matched_rule.rule_id.lower()],
                anomaly_score=0.02,
            )
            apply_decision(
                security_event,
                policy_result=policy_res,
                reason=reason,
            )

        return PolicyEvaluationResult(
            event_id=security_event.identity.event_id,
            verdict=verdict,
            decision_reason=reason,
            matched_rule_id=matched_rule.rule_id,
            matched_rule_name=matched_rule.rule_name,
            matched_rule_type=matched_rule.rule_type.value if hasattr(matched_rule.rule_type, 'value') else str(matched_rule.rule_type),
            risk_level=risk_level,
            execution_allowed=exec_allowed,
            approval_required=approval_req,
        )

# Global default policy engine instance
default_policy_engine = PolicyEngine()
