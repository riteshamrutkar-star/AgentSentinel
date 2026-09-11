from app.audit.repository import get_approval_by_event_id, list_approvals
from app.audit.service import approve_action, record_audit_entry, reject_action
from app.db.crud import get_security_event_by_id
from app.events.factory import apply_decision, create_security_event
from app.events.schema import ActionType, ApprovalStatus, PolicyResult

def test_audit_logging_and_approval_provisioning(db_session):
    event = create_security_event(
        session_id="sess_audit_1",
        agent_id="agent_1",
        user_id="user_1",
        tool_name="drop_database_table",
        arguments_payload={"table_name": "payments"},
        action_type=ActionType.DATABASE,
    )
    apply_decision(
        event,
        policy_result=PolicyResult.REQUIRE_APPROVAL,
        reason="Requires admin approval",
        approval_required=True,
        approval_status=ApprovalStatus.PENDING,
    )

    db_event = record_audit_entry(db_session, event)
    assert db_event is not None
    assert db_event.event_id == event.identity.event_id

    # Verify ApprovalModel record was provisioned
    approval = get_approval_by_event_id(db_session, event.identity.event_id)
    assert approval is not None
    assert approval.status == "PENDING"
    assert approval.decision == "PENDING"

def test_approve_action_flow(db_session):
    event = create_security_event(
        session_id="sess_audit_2",
        agent_id="agent_2",
        user_id="user_2",
        tool_name="drop_database_table",
        arguments_payload={"table_name": "temp_logs"},
        action_type=ActionType.DATABASE,
    )
    apply_decision(
        event,
        policy_result=PolicyResult.REQUIRE_APPROVAL,
        reason="Requires admin approval",
        approval_required=True,
        approval_status=ApprovalStatus.PENDING,
    )
    record_audit_entry(db_session, event)

    # Reviewer approves the action
    updated_event = approve_action(
        db=db_session,
        event_id=event.identity.event_id,
        reviewer="admin_sarah",
        notes="Authorized for scheduled schema maintenance",
    )

    assert updated_event.execution_allowed is True
    assert updated_event.approval_status == "APPROVED"
    assert updated_event.decision_result == "APPROVED"
    assert updated_event.reviewer == "admin_sarah"

    # Verify ApprovalModel is synchronized
    approval = get_approval_by_event_id(db_session, event.identity.event_id)
    assert approval.status == "APPROVED"
    assert approval.decision == "APPROVED"
    assert approval.reviewer == "admin_sarah"
    assert "Authorized" in approval.notes

def test_reject_action_flow(db_session):
    event = create_security_event(
        session_id="sess_audit_3",
        agent_id="agent_3",
        user_id="user_3",
        tool_name="drop_database_table",
        arguments_payload={"table_name": "production_users"},
        action_type=ActionType.DATABASE,
    )
    apply_decision(
        event,
        policy_result=PolicyResult.REQUIRE_APPROVAL,
        reason="Requires admin approval",
        approval_required=True,
        approval_status=ApprovalStatus.PENDING,
    )
    record_audit_entry(db_session, event)

    # Reviewer rejects the action
    updated_event = reject_action(
        db=db_session,
        event_id=event.identity.event_id,
        reviewer="admin_sarah",
        notes="Unauthorized destructive drop rejected",
    )

    assert updated_event.execution_allowed is False
    assert updated_event.approval_status == "REJECTED"
    assert updated_event.decision_result == "REJECTED"
    assert updated_event.reviewer == "admin_sarah"

    # Verify ApprovalModel is synchronized
    approval = get_approval_by_event_id(db_session, event.identity.event_id)
    assert approval.status == "REJECTED"
    assert approval.decision == "REJECTED"
