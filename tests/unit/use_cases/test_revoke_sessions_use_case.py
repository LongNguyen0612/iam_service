"""
Unit tests for Revoke Sessions Use Case
"""

import pytest
from unittest.mock import AsyncMock
from uuid import uuid4

from src.app.use_cases.users.revoke_sessions_use_case import RevokeSessionsUseCase
from src.domain.entities import MembershipRole, Session, User


@pytest.mark.asyncio
async def test_revoke_all_sessions_self_success(mock_uow):
    """Test user successfully revoking their own sessions"""
    user_id = uuid4()
    tenant_id = uuid4()

    # Mock user exists
    mock_uow.users.get_by_id = AsyncMock(return_value=User(id=user_id, email="test@example.com", password_hash="hash"))
    mock_uow.sessions.revoke_all_by_user_id = AsyncMock(return_value=3)
    mock_uow.audit_events.create = AsyncMock()

    use_case = RevokeSessionsUseCase(mock_uow)
    result = await use_case.revoke_all_sessions(
        target_user_id=user_id,
        requesting_user_id=user_id,
        requesting_tenant_id=tenant_id,
        requesting_role=MembershipRole.member.value,
    )

    assert result.is_ok()
    assert result.value["revoked_count"] == 3
    assert result.value["target_user_id"] == str(user_id)
    mock_uow.sessions.revoke_all_by_user_id.assert_called_once_with(user_id)
    mock_uow.commit.assert_called_once()


@pytest.mark.asyncio
async def test_revoke_all_sessions_admin_success(mock_uow):
    """Test admin revoking another user's sessions"""
    admin_id = uuid4()
    target_user_id = uuid4()
    tenant_id = uuid4()

    # Mock target user exists
    mock_uow.users.get_by_id = AsyncMock(return_value=User(id=target_user_id, email="target@example.com", password_hash="hash"))
    mock_uow.sessions.revoke_all_by_user_id = AsyncMock(return_value=2)
    mock_uow.audit_events.create = AsyncMock()

    use_case = RevokeSessionsUseCase(mock_uow)
    result = await use_case.revoke_all_sessions(
        target_user_id=target_user_id,
        requesting_user_id=admin_id,
        requesting_tenant_id=tenant_id,
        requesting_role=MembershipRole.admin.value,
    )

    assert result.is_ok()
    assert result.value["revoked_count"] == 2
    mock_uow.sessions.revoke_all_by_user_id.assert_called_once_with(target_user_id)
    mock_uow.commit.assert_called_once()


@pytest.mark.asyncio
async def test_revoke_all_sessions_forbidden(mock_uow):
    """Test non-admin cannot revoke other user's sessions"""
    user_id = uuid4()
    target_user_id = uuid4()
    tenant_id = uuid4()

    use_case = RevokeSessionsUseCase(mock_uow)
    result = await use_case.revoke_all_sessions(
        target_user_id=target_user_id,
        requesting_user_id=user_id,
        requesting_tenant_id=tenant_id,
        requesting_role=MembershipRole.member.value,
    )

    assert result.is_err()
    assert result.error.code == "FORBIDDEN"


@pytest.mark.asyncio
async def test_revoke_all_sessions_user_not_found(mock_uow):
    """Test error when target user doesn't exist"""
    user_id = uuid4()
    tenant_id = uuid4()

    mock_uow.users.get_by_id = AsyncMock(return_value=None)

    use_case = RevokeSessionsUseCase(mock_uow)
    result = await use_case.revoke_all_sessions(
        target_user_id=user_id,
        requesting_user_id=user_id,
        requesting_tenant_id=tenant_id,
        requesting_role=MembershipRole.member.value,
    )

    assert result.is_err()
    assert result.error.code == "USER_NOT_FOUND"


@pytest.mark.asyncio
async def test_revoke_specific_session_self_success(mock_uow):
    """Test user revoking their own session"""
    user_id = uuid4()
    session_id = uuid4()
    tenant_id = uuid4()

    session = Session(
        id=session_id,
        user_id=user_id,
        tenant_id=tenant_id,
        refresh_token_hash="hash",
        revoked=False,
    )
    mock_uow.sessions.get_by_id = AsyncMock(return_value=session)
    mock_uow.sessions.revoke_by_id = AsyncMock(return_value=True)
    mock_uow.audit_events.create = AsyncMock()

    use_case = RevokeSessionsUseCase(mock_uow)
    result = await use_case.revoke_specific_session(
        session_id=session_id,
        requesting_user_id=user_id,
        requesting_tenant_id=tenant_id,
        requesting_role=MembershipRole.member.value,
    )

    assert result.is_ok()
    assert result.value["session_id"] == str(session_id)
    assert result.value["revoked"] is True
    mock_uow.sessions.revoke_by_id.assert_called_once_with(session_id)
    mock_uow.commit.assert_called_once()


@pytest.mark.asyncio
async def test_revoke_specific_session_not_found(mock_uow):
    """Test error when session doesn't exist"""
    session_id = uuid4()
    user_id = uuid4()
    tenant_id = uuid4()

    mock_uow.sessions.get_by_id = AsyncMock(return_value=None)

    use_case = RevokeSessionsUseCase(mock_uow)
    result = await use_case.revoke_specific_session(
        session_id=session_id,
        requesting_user_id=user_id,
        requesting_tenant_id=tenant_id,
        requesting_role=MembershipRole.member.value,
    )

    assert result.is_err()
    assert result.error.code == "SESSION_NOT_FOUND"


@pytest.mark.asyncio
async def test_revoke_specific_session_already_revoked(mock_uow):
    """Test error when session is already revoked"""
    user_id = uuid4()
    session_id = uuid4()
    tenant_id = uuid4()

    session = Session(
        id=session_id,
        user_id=user_id,
        tenant_id=tenant_id,
        refresh_token_hash="hash",
        revoked=True,  # Already revoked
    )
    mock_uow.sessions.get_by_id = AsyncMock(return_value=session)

    use_case = RevokeSessionsUseCase(mock_uow)
    result = await use_case.revoke_specific_session(
        session_id=session_id,
        requesting_user_id=user_id,
        requesting_tenant_id=tenant_id,
        requesting_role=MembershipRole.member.value,
    )

    assert result.is_err()
    assert result.error.code == "SESSION_ALREADY_REVOKED"


@pytest.mark.asyncio
async def test_revoke_specific_session_forbidden(mock_uow):
    """Test non-admin cannot revoke other user's session"""
    user_id = uuid4()
    other_user_id = uuid4()
    session_id = uuid4()
    tenant_id = uuid4()

    session = Session(
        id=session_id,
        user_id=other_user_id,  # Different user
        tenant_id=tenant_id,
        refresh_token_hash="hash",
        revoked=False,
    )
    mock_uow.sessions.get_by_id = AsyncMock(return_value=session)

    use_case = RevokeSessionsUseCase(mock_uow)
    result = await use_case.revoke_specific_session(
        session_id=session_id,
        requesting_user_id=user_id,
        requesting_tenant_id=tenant_id,
        requesting_role=MembershipRole.member.value,
    )

    assert result.is_err()
    assert result.error.code == "FORBIDDEN"


@pytest.mark.asyncio
async def test_revoke_all_except_current_success(mock_uow):
    """Test user revoking all sessions except current"""
    user_id = uuid4()
    current_session_id = uuid4()
    tenant_id = uuid4()

    current_session = Session(
        id=current_session_id,
        user_id=user_id,
        tenant_id=tenant_id,
        refresh_token_hash="hash",
        revoked=False,
    )
    mock_uow.sessions.get_by_id = AsyncMock(return_value=current_session)
    mock_uow.sessions.revoke_all_except_session = AsyncMock(return_value=4)
    mock_uow.audit_events.create = AsyncMock()

    use_case = RevokeSessionsUseCase(mock_uow)
    result = await use_case.revoke_all_except_current(
        current_session_id=current_session_id,
        requesting_user_id=user_id,
        requesting_tenant_id=tenant_id,
    )

    assert result.is_ok()
    assert result.value["revoked_count"] == 4
    assert result.value["kept_session_id"] == str(current_session_id)
    mock_uow.sessions.revoke_all_except_session.assert_called_once_with(
        user_id, current_session_id
    )
    mock_uow.commit.assert_called_once()


@pytest.mark.asyncio
async def test_revoke_all_except_current_session_not_found(mock_uow):
    """Test error when current session doesn't exist"""
    user_id = uuid4()
    session_id = uuid4()
    tenant_id = uuid4()

    mock_uow.sessions.get_by_id = AsyncMock(return_value=None)

    use_case = RevokeSessionsUseCase(mock_uow)
    result = await use_case.revoke_all_except_current(
        current_session_id=session_id,
        requesting_user_id=user_id,
        requesting_tenant_id=tenant_id,
    )

    assert result.is_err()
    assert result.error.code == "SESSION_NOT_FOUND"


@pytest.mark.asyncio
async def test_revoke_all_except_current_forbidden(mock_uow):
    """Test error when session doesn't belong to user"""
    user_id = uuid4()
    other_user_id = uuid4()
    session_id = uuid4()
    tenant_id = uuid4()

    session = Session(
        id=session_id,
        user_id=other_user_id,  # Different user
        tenant_id=tenant_id,
        refresh_token_hash="hash",
        revoked=False,
    )
    mock_uow.sessions.get_by_id = AsyncMock(return_value=session)

    use_case = RevokeSessionsUseCase(mock_uow)
    result = await use_case.revoke_all_except_current(
        current_session_id=session_id,
        requesting_user_id=user_id,
        requesting_tenant_id=tenant_id,
    )

    assert result.is_err()
    assert result.error.code == "FORBIDDEN"
