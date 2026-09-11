import pytest
from unittest.mock import patch
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from app.db.crud import create_policy, get_or_create_session, list_active_policies, save_security_event
from app.db.models import SessionModel
from app.events.factory import create_security_event

def test_get_or_create_session(db_session):
    s1 = get_or_create_session(db_session, session_id="sess_crud_1", agent_id="agent_1", user_id="user_1")
    assert s1.session_id == "sess_crud_1"

    # Subsequent call returns same session
    s2 = get_or_create_session(db_session, session_id="sess_crud_1", agent_id="agent_1", user_id="user_1")
    assert s2.session_id == s1.session_id

def test_save_security_event_crud(db_session):
    event = create_security_event(
        session_id="sess_crud_evt",
        agent_id="agent_crud",
        user_id="user_crud",
        tool_name="google_search",
        arguments_payload={"query": "test"},
    )
    db_event = save_security_event(db_session, event)
    assert db_event.event_id == event.identity.event_id
    assert db_event.tool_name == "google_search"

def test_create_and_list_policy(db_session):
    policy = create_policy(
        db=db_session,
        policy_name="Test Policy Rule",
        effect="DENY",
        tool_name="sensitive_tool",
        priority=50,
    )
    assert policy.policy_name == "Test Policy Rule"

    policies = list_active_policies(db_session)
    assert any(p.policy_name == "Test Policy Rule" for p in policies)

def test_transaction_rollback_on_commit_failure(db_session):
    # Verify that a commit exception triggers rollback and leaves the session clean
    with patch.object(db_session, "commit", side_effect=SQLAlchemyError("Simulated DB commit error")):
        with pytest.raises(SQLAlchemyError):
            create_policy(
                db=db_session,
                policy_name="Failing Policy",
                effect="ALLOW",
            )

    # Verify session is still valid and usable after rollback
    healthy_session = get_or_create_session(db_session, "sess_after_rollback", "agent_ok", "user_ok")
    assert healthy_session.session_id == "sess_after_rollback"
