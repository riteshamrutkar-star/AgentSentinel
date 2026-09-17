"""
Delegation Context Manager for AgentSentinel Phase 0.4.
Issues, stores, verifies, and revokes bounded delegation tokens,
validating authorized capabilities during delegated tool execution.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.core.logger import logger
from app.db.crud import (
    create_delegation as db_create_delegation,
    get_delegation_by_id as db_get_delegation_by_id,
    list_delegations as db_list_delegations,
    revoke_delegation as db_revoke_delegation,
)
from app.multiagent.config import multiagent_config
from app.multiagent.models import AgentCapability, DelegationContext, utc_now


class DelegationManager:
    """
    Manages the lifecycle and verification of delegated authority tokens.
    Guarantees that delegated agents only execute actions within explicit granted scopes.
    """

    def __init__(self):
        self._cache: Dict[str, DelegationContext] = {}

    def issue_delegation(
        self,
        source_agent_id: str,
        target_agent_id: str,
        session_id: str,
        delegated_capabilities: List[AgentCapability],
        resource_scope: str = "*",
        parent_delegation_id: Optional[str] = None,
        delegation_depth: int = 1,
        expires_at: Optional[datetime] = None,
        provenance_chain: Optional[List[str]] = None,
        metadata: Optional[dict] = None,
        namespace: str = "default",
        db: Optional[Session] = None,
    ) -> DelegationContext:
        """Issues a new verified DelegationContext token."""
        del_id = f"del_{uuid.uuid4().hex[:10]}"
        chain = list(provenance_chain) if provenance_chain else [source_agent_id, target_agent_id]
        meta = metadata or {}

        context = DelegationContext(
            delegation_id=del_id,
            source_agent_id=source_agent_id,
            target_agent_id=target_agent_id,
            session_id=session_id,
            namespace=namespace,
            parent_delegation_id=parent_delegation_id,
            delegated_capabilities=delegated_capabilities,
            resource_scope=resource_scope,
            delegation_depth=delegation_depth,
            status="ACTIVE",
            expires_at=expires_at,
            issued_at=utc_now(),
            provenance_chain=chain,
            metadata=meta,
        )

        self._cache[del_id] = context

        if db:
            try:
                db_create_delegation(
                    db=db,
                    delegation_id=del_id,
                    source_agent_id=source_agent_id,
                    target_agent_id=target_agent_id,
                    session_id=session_id,
                    delegated_capabilities=[c.value for c in delegated_capabilities],
                    resource_scope=resource_scope,
                    delegation_depth=delegation_depth,
                    parent_delegation_id=parent_delegation_id,
                    expires_at=expires_at,
                    provenance_chain=chain,
                    metadata=meta,
                    namespace=namespace,
                )
            except Exception as e:
                logger.warning(f"Failed to persist delegation '{del_id}' to PostgreSQL: {e}")

        logger.info(
            f"Delegation issued: ID='{del_id}' | {source_agent_id} -> {target_agent_id} | "
            f"Caps={[c.value for c in delegated_capabilities]} | Depth={delegation_depth} | Namespace='{namespace}'"
        )
        return context

    def get_delegation(self, delegation_id: str, db: Optional[Session] = None) -> Optional[DelegationContext]:
        """Retrieves a delegation context from memory cache or database."""
        if delegation_id in self._cache:
            return self._cache[delegation_id]

        if db:
            db_del = db_get_delegation_by_id(db, delegation_id)
            if db_del:
                caps = []
                for c in db_del.delegated_capabilities_json or []:
                    try:
                        caps.append(AgentCapability(c))
                    except ValueError:
                        pass

                context = DelegationContext(
                    delegation_id=db_del.delegation_id,
                    source_agent_id=db_del.source_agent_id,
                    target_agent_id=db_del.target_agent_id,
                    session_id=db_del.session_id,
                    namespace=getattr(db_del, "namespace", "default") or "default",
                    parent_delegation_id=db_del.parent_delegation_id,
                    delegated_capabilities=caps,
                    resource_scope=db_del.resource_scope,
                    delegation_depth=db_del.delegation_depth,
                    status=db_del.status,
                    expires_at=db_del.expires_at,
                    issued_at=db_del.created_at,
                    provenance_chain=db_del.provenance_chain_json or [],
                    metadata=db_del.metadata_json or {},
                )
                self._cache[delegation_id] = context
                return context

        return None

    def validate_delegated_tool_call(
        self,
        delegation_id: str,
        executing_agent_id: str,
        tool_name: str,
        target_resource: str = "",
        db: Optional[Session] = None,
    ) -> Tuple[bool, str, Optional[DelegationContext]]:
        """
        Validates whether a tool invocation performed by an agent is authorized under the given delegation token.
        Fails closed on missing token, revoked status, mismatched agent, or capability overreach.
        Returns (is_authorized, reason, delegation_context).
        """
        delegation = self.get_delegation(delegation_id, db)
        if not delegation:
            return False, f"Invalid delegation token '{delegation_id}': Record not found.", None

        # Check status
        if delegation.status != "ACTIVE":
            return False, f"Delegation '{delegation_id}' is no longer active (Status: {delegation.status}).", delegation

        # Check expiration TTL
        if delegation.expires_at and datetime.now(timezone.utc) > delegation.expires_at:
            delegation.status = "EXPIRED"
            return False, f"Delegation '{delegation_id}' has expired.", delegation

        # Check executing agent matches authorized target
        if executing_agent_id != delegation.target_agent_id:
            return (
                False,
                f"Agent impersonation detected: Agent '{executing_agent_id}' attempted to use delegation token "
                f"issued to '{delegation.target_agent_id}'.",
                delegation,
            )

        # Check capability required for tool
        required_cap = multiagent_config.TOOL_TO_CAPABILITY_MAP.get(tool_name)
        if required_cap and required_cap not in delegation.delegated_capabilities:
            granted_str = ", ".join([c.value for c in delegation.delegated_capabilities])
            return (
                False,
                f"Delegation capability scope exceeded: Tool '{tool_name}' requires capability "
                f"'{required_cap.value}', but delegation '{delegation_id}' only granted [{granted_str}].",
                delegation,
            )

        # Check resource scope pattern restriction if not wildcard
        if delegation.resource_scope and delegation.resource_scope != "*":
            res_lower = target_resource.lower().replace("\\", "/")
            scope_lower = delegation.resource_scope.lower().replace("\\", "/")
            if scope_lower not in res_lower:
                return (
                    False,
                    f"Delegation resource scope exceeded: Resource '{target_resource}' does not match "
                    f"allowed scope '{delegation.resource_scope}'.",
                    delegation,
                )

        return True, "Delegation scope authorized.", delegation

    def revoke_delegation(self, delegation_id: str, db: Optional[Session] = None) -> bool:
        """Revokes an active delegation context immediately."""
        delegation = self.get_delegation(delegation_id, db)
        if not delegation:
            return False

        delegation.status = "REVOKED"
        self._cache[delegation_id] = delegation

        if db:
            try:
                db_revoke_delegation(db, delegation_id)
            except Exception as e:
                logger.error(f"Failed to revoke delegation '{delegation_id}' in PostgreSQL: {e}")

        logger.warning(f"SECURITY EVENT: Delegation '{delegation_id}' has been REVOKED.")
        return True

    def list_delegations(
        self,
        session_id: Optional[str] = None,
        db: Optional[Session] = None,
    ) -> List[DelegationContext]:
        """Lists active and historical delegations."""
        if db:
            db_dels = db_list_delegations(db, session_id=session_id)
            if db_dels:
                for d in db_dels:
                    if d.delegation_id not in self._cache:
                        self.get_delegation(d.delegation_id, db)

        result = list(self._cache.values())
        if session_id:
            result = [d for d in result if d.session_id == session_id]
        return result


# Global default DelegationManager singleton
default_delegation_manager = DelegationManager()
