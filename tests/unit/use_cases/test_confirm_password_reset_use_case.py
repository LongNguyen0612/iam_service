"""
Unit tests for ConfirmPasswordResetUseCase

Tests all business logic with mocked dependencies.
"""
import sys
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

# Add monorepo root to Python path for libs access
monorepo_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(monorepo_root))

from libs.result import Error
from src.app.use_cases.auth.confirm_password_reset_use_case import ConfirmPasswordResetUseCase
from src.domain.entities import User, PasswordResetToken


@pytest.fixture
def mock_uow():
    """Mock UnitOfWork with all required repositories"""
    uow = MagicMock()
    uow.__aenter__ = AsyncMock(return_value=uow)
    uow.__aexit__ = AsyncMock()
    uow.commit = AsyncMock()
    uow.rollback = AsyncMock()

    # Mock repositories
    uow.users = MagicMock()
    uow.users.get_by_id = AsyncMock()
    uow.users.update = AsyncMock()

    uow.password_reset_tokens = MagicMock()
    uow.password_reset_tokens.get_by_token_hash = AsyncMock()
    uow.password_reset_tokens.update = AsyncMock()

    uow.sessions = MagicMock()
    uow.sessions.revoke_all_by_user_id = AsyncMock()

    uow.audit_events = MagicMock()
    uow.audit_events.create = AsyncMock()

    return uow


@pytest.mark.asyncio
async def test_successful_password_reset_confirmation(mock_uow):
    """Test successful password reset confirmation - AC-13.1"""
    # Arrange
    user_id = uuid4()
    token_id = uuid4()
    plain_token = "reset_token_12345"
    token_hash = hashlib.sha256(plain_token.encode()).hexdigest()
    new_password = "NewSecurePass123!"

    mock_user = User(
        id=user_id,
        email="user@example.com",
        password_hash="old_hashed_password",
        email_verified=True,
    )

    mock_token = PasswordResetToken(
        id=token_id,
        user_id=user_id,
        token_hash=token_hash,
        used=False,
        expires_at=datetime.utcnow() + timedelta(minutes=30),
    )

    mock_uow.password_reset_tokens.get_by_token_hash.return_value = mock_token
    mock_uow.users.get_by_id.return_value = mock_user
    mock_uow.sessions.revoke_all_by_user_id.return_value = 3  # 3 sessions revoked

    # Mock token update to capture changes
    async def capture_token_update(token):
        return token
    mock_uow.password_reset_tokens.update.side_effect = capture_token_update

    # Mock user update to capture password change
    async def capture_user_update(user):
        return user
    mock_uow.users.update.side_effect = capture_user_update

    use_case = ConfirmPasswordResetUseCase(mock_uow)

    # Act
    result = await use_case.execute(plain_token, new_password)

    # Assert
    assert result.is_ok()
    data = result.value
    assert data.status == "success"
    assert hasattr(data, "message")

    # Verify token was looked up with correct hash
    mock_uow.password_reset_tokens.get_by_token_hash.assert_called_once_with(token_hash)

    # Verify user was fetched
    mock_uow.users.get_by_id.assert_called_once_with(user_id)

    # Verify password was updated (user.update called)
    mock_uow.users.update.assert_called_once()

    # Verify token was marked as used
    mock_uow.password_reset_tokens.update.assert_called_once()

    # Verify all sessions were revoked
    mock_uow.sessions.revoke_all_by_user_id.assert_called_once_with(user_id)

    # Verify audit event was created
    mock_uow.audit_events.create.assert_called_once()

    # Verify transaction committed
    mock_uow.commit.assert_called_once()


@pytest.mark.asyncio
async def test_invalid_token(mock_uow):
    """Test invalid token handling - AC-13.2"""
    # Arrange
    plain_token = "invalid_token"
    new_password = "NewPass123!"

    mock_uow.password_reset_tokens.get_by_token_hash.return_value = None

    use_case = ConfirmPasswordResetUseCase(mock_uow)

    # Act
    result = await use_case.execute(plain_token, new_password)

    # Assert
    assert result.is_err()
    assert result.error.code == "INVALID_TOKEN"

    # Verify no updates were made
    mock_uow.users.update.assert_not_called()
    mock_uow.password_reset_tokens.update.assert_not_called()
    mock_uow.sessions.revoke_all_by_user_id.assert_not_called()
    mock_uow.commit.assert_not_called()


@pytest.mark.asyncio
async def test_expired_token(mock_uow):
    """Test expired token handling - AC-13.3"""
    # Arrange
    user_id = uuid4()
    plain_token = "expired_token"
    token_hash = hashlib.sha256(plain_token.encode()).hexdigest()
    new_password = "NewPass123!"

    # Token expired 2 hours ago
    mock_token = PasswordResetToken(
        id=uuid4(),
        user_id=user_id,
        token_hash=token_hash,
        used=False,
        expires_at=datetime.utcnow() - timedelta(hours=2),
    )

    mock_uow.password_reset_tokens.get_by_token_hash.return_value = mock_token

    use_case = ConfirmPasswordResetUseCase(mock_uow)

    # Act
    result = await use_case.execute(plain_token, new_password)

    # Assert
    assert result.is_err()
    assert result.error.code == "TOKEN_EXPIRED"

    # Verify no updates were made
    mock_uow.users.update.assert_not_called()
    mock_uow.commit.assert_not_called()


@pytest.mark.asyncio
async def test_already_used_token(mock_uow):
    """Test already used token handling"""
    # Arrange
    user_id = uuid4()
    plain_token = "used_token"
    token_hash = hashlib.sha256(plain_token.encode()).hexdigest()
    new_password = "NewPass123!"

    # Token already used
    mock_token = PasswordResetToken(
        id=uuid4(),
        user_id=user_id,
        token_hash=token_hash,
        used=True,  # Already used
        expires_at=datetime.utcnow() + timedelta(minutes=30),
    )

    mock_uow.password_reset_tokens.get_by_token_hash.return_value = mock_token

    use_case = ConfirmPasswordResetUseCase(mock_uow)

    # Act
    result = await use_case.execute(plain_token, new_password)

    # Assert
    assert result.is_err()
    assert result.error.code == "TOKEN_ALREADY_USED"

    # Verify no updates were made
    mock_uow.users.update.assert_not_called()
    mock_uow.commit.assert_not_called()


@pytest.mark.asyncio
async def test_password_too_short(mock_uow):
    """Test password validation - too short - AC-13.4"""
    # Arrange
    plain_token = "valid_token"
    new_password = "short"  # Less than 8 chars

    use_case = ConfirmPasswordResetUseCase(mock_uow)

    # Act
    result = await use_case.execute(plain_token, new_password)

    # Assert
    assert result.is_err()
    assert result.error.code == "INVALID_PASSWORD"

    # Verify no database operations were performed
    mock_uow.password_reset_tokens.get_by_token_hash.assert_not_called()
    mock_uow.commit.assert_not_called()


@pytest.mark.asyncio
async def test_password_is_hashed_with_bcrypt(mock_uow):
    """Test that password is hashed with bcrypt before storing"""
    # Arrange
    user_id = uuid4()
    plain_token = "reset_token"
    token_hash = hashlib.sha256(plain_token.encode()).hexdigest()
    new_password = "NewSecurePass123!"

    mock_user = User(
        id=user_id,
        email="user@example.com",
        password_hash="old_hashed_password",
        email_verified=True,
    )

    mock_token = PasswordResetToken(
        id=uuid4(),
        user_id=user_id,
        token_hash=token_hash,
        used=False,
        expires_at=datetime.utcnow() + timedelta(minutes=30),
    )

    mock_uow.password_reset_tokens.get_by_token_hash.return_value = mock_token
    mock_uow.users.get_by_id.return_value = mock_user
    mock_uow.sessions.revoke_all_by_user_id.return_value = 0

    # Capture updated user
    updated_user = None
    async def capture_user_update(user):
        nonlocal updated_user
        updated_user = user
        return user
    mock_uow.users.update.side_effect = capture_user_update

    use_case = ConfirmPasswordResetUseCase(mock_uow)

    # Act
    result = await use_case.execute(plain_token, new_password)

    # Assert
    assert result.is_ok()
    assert updated_user is not None
    assert updated_user.password_hash != new_password  # Should be hashed
    assert updated_user.password_hash != "old_hashed_password"  # Should be changed


@pytest.mark.asyncio
async def test_all_sessions_revoked(mock_uow):
    """Test that all user sessions are revoked for security"""
    # Arrange
    user_id = uuid4()
    plain_token = "reset_token"
    token_hash = hashlib.sha256(plain_token.encode()).hexdigest()
    new_password = "NewPass123!"

    mock_user = User(
        id=user_id,
        email="user@example.com",
        password_hash="old_hashed_password",
        email_verified=True,
    )

    mock_token = PasswordResetToken(
        id=uuid4(),
        user_id=user_id,
        token_hash=token_hash,
        used=False,
        expires_at=datetime.utcnow() + timedelta(minutes=30),
    )

    mock_uow.password_reset_tokens.get_by_token_hash.return_value = mock_token
    mock_uow.users.get_by_id.return_value = mock_user
    mock_uow.sessions.revoke_all_by_user_id.return_value = 5  # 5 sessions revoked

    use_case = ConfirmPasswordResetUseCase(mock_uow)

    # Act
    result = await use_case.execute(plain_token, new_password)

    # Assert
    assert result.is_ok()

    # Verify all sessions were revoked for this user
    mock_uow.sessions.revoke_all_by_user_id.assert_called_once_with(user_id)


@pytest.mark.asyncio
async def test_token_marked_as_used(mock_uow):
    """Test that token is marked as used after successful reset"""
    # Arrange
    user_id = uuid4()
    plain_token = "reset_token"
    token_hash = hashlib.sha256(plain_token.encode()).hexdigest()
    new_password = "NewPass123!"

    mock_user = User(
        id=user_id,
        email="user@example.com",
        password_hash="old_hashed_password",
        email_verified=True,
    )

    mock_token = PasswordResetToken(
        id=uuid4(),
        user_id=user_id,
        token_hash=token_hash,
        used=False,
        expires_at=datetime.utcnow() + timedelta(minutes=30),
    )

    mock_uow.password_reset_tokens.get_by_token_hash.return_value = mock_token
    mock_uow.users.get_by_id.return_value = mock_user
    mock_uow.sessions.revoke_all_by_user_id.return_value = 0

    # Capture updated token
    updated_token = None
    async def capture_token_update(token):
        nonlocal updated_token
        updated_token = token
        return token
    mock_uow.password_reset_tokens.update.side_effect = capture_token_update

    use_case = ConfirmPasswordResetUseCase(mock_uow)

    # Act
    result = await use_case.execute(plain_token, new_password)

    # Assert
    assert result.is_ok()
    assert updated_token is not None
    assert updated_token.used is True


@pytest.mark.asyncio
async def test_audit_event_created(mock_uow):
    """Test that audit event is created for security tracking"""
    # Arrange
    user_id = uuid4()
    token_id = uuid4()
    plain_token = "reset_token"
    token_hash = hashlib.sha256(plain_token.encode()).hexdigest()
    new_password = "NewPass123!"

    mock_user = User(
        id=user_id,
        email="user@example.com",
        password_hash="old_hashed_password",
        email_verified=True,
    )

    mock_token = PasswordResetToken(
        id=token_id,
        user_id=user_id,
        token_hash=token_hash,
        used=False,
        expires_at=datetime.utcnow() + timedelta(minutes=30),
    )

    mock_uow.password_reset_tokens.get_by_token_hash.return_value = mock_token
    mock_uow.users.get_by_id.return_value = mock_user
    mock_uow.sessions.revoke_all_by_user_id.return_value = 2

    # Capture audit event
    created_audit_event = None
    async def capture_audit_event(event):
        nonlocal created_audit_event
        created_audit_event = event
        return event
    mock_uow.audit_events.create.side_effect = capture_audit_event

    use_case = ConfirmPasswordResetUseCase(mock_uow)

    # Act
    result = await use_case.execute(plain_token, new_password)

    # Assert
    assert result.is_ok()

    # Verify audit event was created
    mock_uow.audit_events.create.assert_called_once()

    # Verify audit event properties
    assert created_audit_event is not None
    assert created_audit_event.user_id == user_id
    assert created_audit_event.action == "password_reset_confirmed"
    assert "token_id" in created_audit_event.event_metadata
    assert "sessions_revoked" in created_audit_event.event_metadata
    assert created_audit_event.event_metadata["sessions_revoked"] == 2


@pytest.mark.asyncio
async def test_user_not_found(mock_uow):
    """Test handling when user is not found (edge case)"""
    # Arrange
    user_id = uuid4()
    plain_token = "reset_token"
    token_hash = hashlib.sha256(plain_token.encode()).hexdigest()
    new_password = "NewPass123!"

    mock_token = PasswordResetToken(
        id=uuid4(),
        user_id=user_id,
        token_hash=token_hash,
        used=False,
        expires_at=datetime.utcnow() + timedelta(minutes=30),
    )

    mock_uow.password_reset_tokens.get_by_token_hash.return_value = mock_token
    mock_uow.users.get_by_id.return_value = None  # User not found

    use_case = ConfirmPasswordResetUseCase(mock_uow)

    # Act
    result = await use_case.execute(plain_token, new_password)

    # Assert
    assert result.is_err()
    assert result.error.code == "USER_NOT_FOUND"

    # Verify no updates were made
    mock_uow.users.update.assert_not_called()
    mock_uow.commit.assert_not_called()
