from typing import List
from app.policy.schemas import PolicyRule, RuleEffect, RuleType

def get_default_policy_rules() -> List[PolicyRule]:
    """Returns the default set of explicit RBAC, ABAC, and Security rules."""
    return [
        # --- 1. Security Block Rules (Highest Priority: 1 - 9) ---
        PolicyRule(
            rule_id="SEC_BLOCK_CREDENTIALS",
            rule_name="Block Privileged Credential Files",
            rule_type=RuleType.SECURITY,
            effect=RuleEffect.BLOCK,
            role="*",
            tool_name="*",
            action_type="*",
            resource_pattern="*/.ssh/*|*/id_rsa*|*/etc/shadow|*/etc/passwd|*.env|*aws/credentials*",
            priority=1,
            description="Prohibits reading or exfiltrating private SSH keys, shadow files, or environment API secrets.",
            sensitivity_level="CRITICAL",
        ),
        PolicyRule(
            rule_id="SEC_BLOCK_SHELL_DESTRUCTION",
            rule_name="Block Destructive Shell Commands",
            rule_type=RuleType.SECURITY,
            effect=RuleEffect.BLOCK,
            role="*",
            tool_name="*",
            action_type="EXECUTE",
            resource_pattern="*rm -rf*|*format_disk*|*chmod 777 /|*mkfs*",
            priority=2,
            description="Prohibits dangerous shell execution commands that cause permanent system destruction.",
            sensitivity_level="CRITICAL",
        ),

        # --- 2. ABAC Attribute-Based Rules (Priority: 10 - 19) ---
        PolicyRule(
            rule_id="ABAC_DESTRUCTIVE_DB_APPROVAL",
            rule_name="Require Approval for Destructive Database Schema Operations",
            rule_type=RuleType.ABAC,
            effect=RuleEffect.REQUIRE_APPROVAL,
            role="*",
            tool_name="drop_table|drop_database|delete_all",
            action_type="DATABASE",
            resource_pattern="*",
            priority=10,
            description="Requires administrator sign-off before executing destructive database schema drop operations.",
            sensitivity_level="HIGH",
        ),
        PolicyRule(
            rule_id="ABAC_HIGH_SENSITIVITY_APPROVAL",
            rule_name="Require Approval for High Sensitivity System Resources",
            rule_type=RuleType.ABAC,
            effect=RuleEffect.REQUIRE_APPROVAL,
            role="*",
            tool_name="*",
            action_type="*",
            resource_pattern="*production*|*system_config*",
            priority=15,
            description="Requires human verification when accessing production data or sensitive system configurations.",
            sensitivity_level="HIGH",
        ),

        # --- 3. RBAC Role-Based Rules (Priority: 20 - 99) ---
        PolicyRule(
            rule_id="RBAC_RESEARCH_READ_ONLY",
            rule_name="Allow Research Assistant Read-Only Network Actions",
            rule_type=RuleType.RBAC,
            effect=RuleEffect.ALLOW,
            role="research_assistant",
            tool_name="google_search|arxiv_fetch|fetch_web_content",
            action_type="NETWORK",
            resource_pattern="*",
            priority=20,
            description="Permits research assistant role to perform read-only web and network queries.",
            sensitivity_level="LOW",
        ),
        PolicyRule(
            rule_id="RBAC_CODE_ASSISTANT_WORKSPACE",
            rule_name="Allow Code Assistant Workspace File Actions",
            rule_type=RuleType.RBAC,
            effect=RuleEffect.ALLOW,
            role="code_assistant",
            tool_name="read_file|write_file|list_dir",
            action_type="READ|WRITE",
            resource_pattern="*",
            priority=25,
            description="Permits code assistant role to read and write files within approved workspace bounds.",
            sensitivity_level="LOW",
        ),

        # --- 4. Default Fallback Rule (Priority: 1000) ---
        PolicyRule(
            rule_id="RBAC_DEFAULT_ALLOW",
            rule_name="Default Allow for Non-Sensitive Tool Actions",
            rule_type=RuleType.RBAC,
            effect=RuleEffect.ALLOW,
            role="*",
            tool_name="*",
            action_type="*",
            resource_pattern="*",
            priority=1000,
            description="Default permission permitting un-flagged routine tool invocations.",
            sensitivity_level="LOW",
        ),
    ]
