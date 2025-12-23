"""
Unit tests for ResendVerificationUseCase

Tests all business logic with mocked dependencies.
"""
import sys
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

# Add monorepo root to Python path for libs access
monorepo_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(monorepo_root))

from libs.result import Error
from src.app.use_cases.auth.resend_verification_use_case import ResendVerificationUseCase
from src.domain.entities import User


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
    uow.users.get_by_email = AsyncMock()
    uow.users.update = AsyncMock()

    return uow


@pytest.mark.asyncio
async def test_successful_resend_verification(mock_uow):
    """Test successful resend for unverified user - AC-11.1"""
    # Arrange
    user_id = uuid4()
    email = "user@example.com"
    old_token = "old_verification_token"
    old_expiry = datetime.utcnow() + timedelta(hours=1)

    mock_user = User(
        id=user_id,
        email=email,
        password_hash="hashed_password",
        email_verified=False,
        email_verification_token=old_token,
        email_verification_expires_at=old_expiry
    )
    mock_uow.users.get_by_email.return_value = mock_user

    use_case = ResendVerificationUseCase(mock_uow)

    # Act
    result = await use_case.execute(email)

    # Assert
    assert result.is_ok()
    data = result.value
    assert data.status == "sent"
    assert hasattr(data, "message")

    # Verify user was updated
    mock_uow.users.update.assert_called_once()
    updated_user = mock_uow.users.update.call_args[0][0]

    # New token should be generated
    assert updated_user.email_verification_token is not None
    assert updated_user.email_verification_token != old_token

    # Expiry should be reset to ~24 hours
    assert updated_user.email_verification_expires_at is not None
    assert updated_user.email_verification_expires_at > old_expiry

    # User should still be unverified
    assert updated_user.email_verified is False

    # Verify transaction committed
    mock_uow.commit.assert_called_once()


@pytest.mark.asyncio
async def test_resend_already_verified(mock_uow):
    """Test resend for already verified user - AC-11.2"""
    # Arrange
    user_id = uuid4()
    email = "verified@example.com"

    mock_user = User(
        id=user_id,
        email=email,
        password_hash="hashed_password",
        email_verified=True,  # Already verified
        email_verification_token=None,
        email_verification_expires_at=None
    )
    mock_uow.users.get_by_email.return_value = mock_user

    use_case = ResendVerificationUseCase(mock_uow)

    # Act
    result = await use_case.execute(email)

    # Assert
    assert result.is_ok()
    data = result.value
    assert data.status == "already_verified"
    assert "already" in data.message.lower() or "verified" in data.message.lower()

    # Verify no updates (no token generated)
    mock_uow.users.update.assert_not_called()
    mock_uow.commit.assert_not_called()


@pytest.mark.asyncio
async def test_resend_non_existent_email(mock_uow):
    """Test resend for non-existent email - No enumeration"""
    # Arrange
    email = "nonexistent@example.com"
    mock_uow.users.get_by_email.return_value = None

    use_case = ResendVerificationUseCase(mock_uow)

    # Act
    result = await use_case.execute(email)

    # Assert - returns success to prevent email enumeration
    assert result.is_ok()
    data = result.value
    assert data.status == "sent"
    assert hasattr(data, "message")

    # Verify no updates
    mock_uow.users.update.assert_not_called()
    mock_uow.commit.assert_not_called()


@pytest.mark.asyncio
async def test_resend_invalidates_old_token(mock_uow):
    """Test that resend generates a new token different from old one"""
    # Arrange
    user_id = uuid4()
    email = "user@example.com"
    old_token = "old_token_12345"

    mock_user = User(
        id=user_id,
        email=email,
        password_hash="hashed_password",
        email_verified=False,
        email_verification_token=old_token,
        email_verification_expires_at=datetime.utcnow() + timedelta(hours=1)
    )
    mock_uow.users.get_by_email.return_value = mock_user

    use_case = ResendVerificationUseCase(mock_uow)

    # Act
    result = await use_case.execute(email)

    # Assert
    assert result.is_ok()

    # Verify new token is different
    mock_uow.users.update.assert_called_once()
    updated_user = mock_uow.users.update.call_args[0][0]

    assert updated_user.email_verification_token != old_token
    assert updated_user.email_verification_token is not None
    assert len(updated_user.email_verification_token) > 0


@pytest.mark.asyncio
async def test_resend_extends_expiry_to_24_hours(mock_uow):
    """Test that resend resets expiry to ~24 hours from now"""
    # Arrange
    user_id = uuid4()
    email = "user@example.com"

    # Token expiring in 1 hour
    old_expiry = datetime.utcnow() + timedelta(hours=1)

    mock_user = User(
        id=user_id,
        email=email,
        password_hash="hashed_password",
        email_verified=False,
        email_verification_token="old_token",
        email_verification_expires_at=old_expiry
    )
    mock_uow.users.get_by_email.return_value = mock_user

    use_case = ResendVerificationUseCase(mock_uow)

    # Act
    result = await use_case.execute(email)

    # Assert
    assert result.is_ok()

    # Verify expiry was extended to ~24 hours
    mock_uow.users.update.assert_called_once()
    updated_user = mock_uow.users.update.call_args[0][0]

    new_expiry = updated_user.email_verification_expires_at
    time_until_expiry = new_expiry - datetime.utcnow()

    # Should be approximately 24 hours (23-25 hours range to account for execution time)
    assert time_until_expiry.total_seconds() > 23 * 3600  # More than 23 hours
    assert time_until_expiry.total_seconds() < 25 * 3600  # Less than 25 hours


@pytest.mark.asyncio
async def test_resend_preserves_user_data(mock_uow):
    """Test that resend only updates token fields, not other user data"""
    # Arrange
    user_id = uuid4()
    email = "user@example.com"
    original_password_hash = "original_hash"

    mock_user = User(
        id=user_id,
        email=email,
        password_hash=original_password_hash,
        email_verified=False,
        email_verification_token="old_token",
        email_verification_expires_at=datetime.utcnow() + timedelta(hours=1)
    )
    mock_uow.users.get_by_email.return_value = mock_user

    use_case = ResendVerificationUseCase(mock_uow)

    # Act
    result = await use_case.execute(email)

    # Assert
    assert result.is_ok()

    # Verify only token fields changed
    mock_uow.users.update.assert_called_once()
    updated_user = mock_uow.users.update.call_args[0][0]

    assert updated_user.id == user_id
    assert updated_user.email == email
    assert updated_user.password_hash == original_password_hash
    assert updated_user.email_verified is False


@pytest.mark.asyncio
async def test_resend_token_is_secure_random(mock_uow):
    """Test that generated token is cryptographically secure (32+ chars)"""
    # Arrange
    user_id = uuid4()
    email = "user@example.com"

    mock_user = User(
        id=user_id,
        email=email,
        password_hash="hashed_password",
        email_verified=False,
        email_verification_token="old_token",
        email_verification_expires_at=datetime.utcnow() + timedelta(hours=1)
    )
    mock_uow.users.get_by_email.return_value = mock_user

    use_case = ResendVerificationUseCase(mock_uow)

    # Act
    result = await use_case.execute(email)

    # Assert
    assert result.is_ok()

    # Verify token is secure (at least 32 chars from secrets.token_urlsafe(32))
    mock_uow.users.update.assert_called_once()
    updated_user = mock_uow.users.update.call_args[0][0]

    assert updated_user.email_verification_token is not None
    assert len(updated_user.email_verification_token) >= 32  # Should be ~43 chars for urlsafe(32)
