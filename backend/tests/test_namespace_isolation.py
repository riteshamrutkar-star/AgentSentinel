"""
AgentSentinel Phase 0.9: Durable Namespace Security Boundary & Cross-Namespace Denial Tests.
Verifies that:
1. Namespaces are enforced at identity authorization (Identity -> Allowed Namespaces -> Requested Namespace).
2. A caller authorized for 'engineering' cannot read or mutate 'finance' (HTTP 403 Forbidden).
3. PostgreSQL queries filter strictly by namespace, guaranteeing zero data leakage across tenants/boundaries.
4. Multi-agent delegations, approvals, and alerts enforce namespace segregation.
"""

import uuid
import pytest
from fastapi import HTTPException
from app.auth.models import AdminRole, AuthenticatedIdentity
from app.auth.dependencies import require_namespace_access
from app.db.crud import (
    save_security_event,
    list_security_events,
    list_security_alerts,
)
from app.db.models import ApprovalModel, SecurityAlertModel, AgentModel, DelegationModel
from app.events.factory import create_security_event
from app.events.schema import ActionType
from app.db.session import SessionLocal


def test_cross_namespace_access_denial():
    """Identity authorized only for 'engineering' must be denied access to 'finance'."""
    engineering_identity = AuthenticatedIdentity(
        identity_id="usr_eng_01",
        name="Engineering Lead",
        role=AdminRole.OPERATOR,
        allowed_namespaces=["engineering"],
    )

    # 1. Allowed access to engineering namespace
    authorized_ns = require_namespace_access(x_namespace="engineering", identity=engineering_identity)
    assert authorized_ns == "engineering"

    # 2. Denied access to finance namespace (HTTP 403)
    with pytest.raises(HTTPException) as exc_info:
        require_namespace_access(x_namespace="finance", identity=engineering_identity)
    assert exc_info.value.status_code == 403
    assert "Unauthorized namespace access" in exc_info.value.detail
    assert "cannot access 'finance'" in exc_info.value.detail


def test_default_deny_when_no_namespaces_allowed():
    """Identity with empty allowed_namespaces must be denied all namespaces."""
    restricted_identity = AuthenticatedIdentity(
        identity_id="usr_none_01",
        name="Restricted User",
        role=AdminRole.VIEWER,
        allowed_namespaces=[],
    )

    with pytest.raises(HTTPException) as exc_info:
        require_namespace_access(x_namespace="default", identity=restricted_identity)
    assert exc_info.value.status_code == 403


def test_wildcard_namespace_access():
    """Identity with '*' allowed namespace can access any requested namespace."""
    admin_identity = AuthenticatedIdentity(
        identity_id="usr_admin_01",
        name="Platform Admin",
        role=AdminRole.PLATFORM_ADMIN,
        allowed_namespaces=["*"],
    )

    assert require_namespace_access(x_namespace="production", identity=admin_identity) == "production"
    assert require_namespace_access(x_namespace="finance", identity=admin_identity) == "finance"
    assert require_namespace_access(x_namespace="healthcare", identity=admin_identity) == "healthcare"


def test_durable_database_namespace_isolation():
    """Events saved with distinct namespaces must not leak in cross-namespace queries."""
    db = SessionLocal()
    try:
        # Create event in engineering namespace
        evt_eng = create_security_event(
            session_id=f"sess_eng_{uuid.uuid4().hex[:6]}",
            agent_id="agent_eng",
            user_id="user_eng",
            tool_name="git_commit",
            action_type=ActionType.WRITE,
            arguments_payload={"commit_msg": "feat: init"},
        )
        evt_eng.namespace = "engineering"
        saved_eng = save_security_event(db, evt_eng)
        assert saved_eng.namespace == "engineering"

        # Create event in finance namespace
        evt_fin = create_security_event(
            session_id=f"sess_fin_{uuid.uuid4().hex[:6]}",
            agent_id="agent_fin",
            user_id="user_fin",
            tool_name="transfer_funds",
            action_type=ActionType.EXECUTE,
            arguments_payload={"amount": 100},
        )
        evt_fin.namespace = "finance"
        saved_fin = save_security_event(db, evt_fin)
        assert saved_fin.namespace == "finance"

        # Query engineering: must contain saved_eng, must NOT contain saved_fin
        eng_events = list_security_events(db=db, namespace="engineering")
        eng_event_ids = [e.event_id for e in eng_events]
        assert saved_eng.event_id in eng_event_ids
        assert saved_fin.event_id not in eng_event_ids

        # Query finance: must contain saved_fin, must NOT contain saved_eng
        fin_events = list_security_events(db=db, namespace="finance")
        fin_event_ids = [e.event_id for e in fin_events]
        assert saved_fin.event_id in fin_event_ids
        assert saved_eng.event_id not in fin_event_ids

    finally:
        db.close()


def test_durable_approval_and_alert_namespace_isolation():
    """Approvals and alerts must be isolated by namespace in PostgreSQL."""
    db = SessionLocal()
    try:
        # 0. Create event first to satisfy foreign key constraint
        evt_hc = create_security_event(
            session_id=f"sess_hc_{uuid.uuid4().hex[:6]}",
            agent_id="agent_med",
            user_id="doctor_01",
            tool_name="access_patient_records",
            action_type=ActionType.READ,
            arguments_payload={"patient_id": "P123"},
        )
        evt_hc.namespace = "healthcare"
        saved_evt = save_security_event(db, evt_hc)

        # 1. Direct approval record in healthcare namespace
        appr_id = f"appr_{uuid.uuid4().hex[:8]}"
        appr_hc = ApprovalModel(
            approval_id=appr_id,
            event_id=saved_evt.event_id,
            namespace="healthcare",
            status="PENDING",
            decision="PENDING",
        )
        db.add(appr_hc)

        # 2. Alert in healthcare namespace
        alert_id = f"alert_{uuid.uuid4().hex[:8]}"
        alert_hc = SecurityAlertModel(
            alert_id=alert_id,
            alert_type="HIPAA_VIOLATION_ATTEMPT",
            severity="CRITICAL",
            title="Unauthorized Patient Record Access",
            namespace="healthcare",
            status="NEW",
        )
        db.add(alert_hc)
        db.commit()

        # Query approvals for finance: must not find healthcare approval
        fin_approvals = db.query(ApprovalModel).filter(ApprovalModel.namespace == "finance").all()
        fin_appr_ids = [a.approval_id for a in fin_approvals]
        assert appr_id not in fin_appr_ids

        # Query approvals for healthcare: must find healthcare approval
        hc_approvals = db.query(ApprovalModel).filter(ApprovalModel.namespace == "healthcare").all()
        hc_appr_ids = [a.approval_id for a in hc_approvals]
        assert appr_id in hc_appr_ids

        # Query alerts for finance: must not find healthcare alert
        fin_alerts = list_security_alerts(db=db, namespace="finance")
        fin_alert_ids = [a.alert_id for a in fin_alerts]
        assert alert_id not in fin_alert_ids

        # Query alerts for healthcare: must find healthcare alert
        hc_alerts = list_security_alerts(db=db, namespace="healthcare")
        hc_alert_ids = [a.alert_id for a in hc_alerts]
        assert alert_id in hc_alert_ids

    finally:
        db.close()


def test_multiagent_delegation_namespace_isolation():
    """Multi-agent delegations must preserve and isolate namespaces in PostgreSQL."""
    db = SessionLocal()
    try:
        # Register agent in engineering
        agent_id = f"agent_eng_{uuid.uuid4().hex[:6]}"
        agent = AgentModel(
            agent_id=agent_id,
            name="Engineering Worker",
            role="developer",
            capabilities_json=["git_push", "build"],
            trust_level="STANDARD",
            namespace="engineering",
        )
        db.add(agent)

        # Create delegation within engineering
        del_id = f"del_{uuid.uuid4().hex[:8]}"
        delegation = DelegationModel(
            delegation_id=del_id,
            session_id=f"sess_del_{uuid.uuid4().hex[:6]}",
            source_agent_id="agent_supervisor",
            target_agent_id=agent_id,
            delegated_capabilities_json=["build"],
            status="ACTIVE",
            namespace="engineering",
        )
        db.add(delegation)
        db.commit()

        # Query delegations in finance: must not see engineering delegation
        fin_dels = db.query(DelegationModel).filter(DelegationModel.namespace == "finance").all()
        fin_del_ids = [d.delegation_id for d in fin_dels]
        assert del_id not in fin_del_ids

        # Query delegations in engineering: must find delegation
        eng_dels = db.query(DelegationModel).filter(DelegationModel.namespace == "engineering").all()
        eng_del_ids = [d.delegation_id for d in eng_dels]
        assert del_id in eng_del_ids

    finally:
        db.close()
