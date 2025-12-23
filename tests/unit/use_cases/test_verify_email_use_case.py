"""
Unit tests for VerifyEmailUseCase

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
from src.app.use_cases.auth.verify_email_use_case import VerifyEmailUseCase
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
    uow.users.get_by_verification_token = AsyncMock()
    uow.users.update = AsyncMock()

    uow.audit_events = MagicMock()
    uow.audit_events.create = AsyncMock()

    return uow


@pytest.mark.asyncio
async def test_successful_email_verification(mock_uow):
    """Test successful email verification - AC-10.1"""
    # Arrange
    user_id = uuid4()
    token = "valid_verification_token"

    mock_user = User(
        id=user_id,
        email="user@example.com",
        password_hash="hashed_password",
        email_verified=False,
        email_verification_token=token,
        email_verification_expires_at=datetime.utcnow() + timedelta(hours=23)
    )
    mock_uow.users.get_by_verification_token.return_value = mock_user

    use_case = VerifyEmailUseCase(mock_uow)

    # Act
    result = await use_case.execute(token)

    # Assert
    assert result.is_ok()
    data = result.value
    assert data.status == "verified"
    assert "successfully" in data.message.lower()

    # Verify user was updated
    mock_uow.users.update.assert_called_once()
    updated_user = mock_uow.users.update.call_args[0][0]
    assert updated_user.email_verified is True
    assert updated_user.email_verification_token is None
    assert updated_user.email_verification_expires_at is None

    # Verify audit event was created
    mock_uow.audit_events.create.assert_called_once()
    audit_call = mock_uow.audit_events.create.call_args[0][0]
    assert audit_call.action == "email_verified"
    assert audit_call.user_id == user_id

    # Verify transaction committed
    mock_uow.commit.assert_called_once()


@pytest.mark.asyncio
async def test_invalid_verification_token(mock_uow):
    """Test verification with invalid token - AC-10.3"""
    # Arrange
    mock_uow.users.get_by_verification_token.return_value = None

    use_case = VerifyEmailUseCase(mock_uow)

    # Act
    result = await use_case.execute("invalid_token")

    # Assert
    assert result.is_err()
    assert result.error.code == "INVALID_TOKEN"
    assert "invalid" in result.error.message.lower()

    # Verify no updates or commits
    mock_uow.users.update.assert_not_called()
    mock_uow.audit_events.create.assert_not_called()
    mock_uow.commit.assert_not_called()


@pytest.mark.asyncio
async def test_expired_verification_token(mock_uow):
    """Test verification with expired token - AC-10.2"""
    # Arrange
    user_id = uuid4()
    token = "expired_token"

    mock_user = User(
        id=user_id,
        email="user@example.com",
        password_hash="hashed_password",
        email_verified=False,
        email_verification_token=token,
        email_verification_expires_at=datetime.utcnow() - timedelta(hours=25)  # Expired
    )
    mock_uow.users.get_by_verification_token.return_value = mock_user

    use_case = VerifyEmailUseCase(mock_uow)

    # Act
    result = await use_case.execute(token)

    # Assert
    assert result.is_err()
    assert result.error.code == "TOKEN_EXPIRED"
    assert "expired" in result.error.message.lower()

    # Verify no updates or commits
    mock_uow.users.update.assert_not_called()
    mock_uow.audit_events.create.assert_not_called()
    mock_uow.commit.assert_not_called()


@pytest.mark.asyncio
async def test_already_verified_user(mock_uow):
    """Test verification of already verified user - AC-10.4"""
    # Arrange
    user_id = uuid4()
    token = "some_token"

    mock_user = User(
        id=user_id,
        email="user@example.com",
        password_hash="hashed_password",
        email_verified=True,  # Already verified
        email_verification_token=token,
        email_verification_expires_at=datetime.utcnow() + timedelta(hours=23)
    )
    mock_uow.users.get_by_verification_token.return_value = mock_user

    use_case = VerifyEmailUseCase(mock_uow)

    # Act
    result = await use_case.execute(token)

    # Assert
    assert result.is_ok()
    data = result.value
    assert data.status == "verified"
    assert "already" in data.message.lower()

    # Verify no updates (idempotent)
    mock_uow.users.update.assert_not_called()
    mock_uow.audit_events.create.assert_not_called()
    mock_uow.commit.assert_not_called()


@pytest.mark.asyncio
async def test_missing_expiry_date(mock_uow):
    """Test verification when expiry date is missing (data corruption scenario)"""
    # Arrange
    user_id = uuid4()
    token = "token_with_no_expiry"

    mock_user = User(
        id=user_id,
        email="user@example.com",
        password_hash="hashed_password",
        email_verified=False,
        email_verification_token=token,
        email_verification_expires_at=None  # Missing expiry
    )
    mock_uow.users.get_by_verification_token.return_value = mock_user

    use_case = VerifyEmailUseCase(mock_uow)

    # Act
    result = await use_case.execute(token)

    # Assert
    assert result.is_err()
    assert result.error.code == "INVALID_TOKEN"
    assert "invalid" in result.error.message.lower()

    # Verify no updates or commits
    mock_uow.users.update.assert_not_called()
    mock_uow.commit.assert_not_called()


@pytest.mark.asyncio
async def test_verification_token_at_boundary(mock_uow):
    """Test verification with token at exact expiry boundary"""
    # Arrange
    user_id = uuid4()
    token = "boundary_token"

    # Token expires in exactly 1 second
    mock_user = User(
        id=user_id,
        email="user@example.com",
        password_hash="hashed_password",
        email_verified=False,
        email_verification_token=token,
        email_verification_expires_at=datetime.utcnow() + timedelta(seconds=1)
    )
    mock_uow.users.get_by_verification_token.return_value = mock_user

    use_case = VerifyEmailUseCase(mock_uow)

    # Act
    result = await use_case.execute(token)

    # Assert - should succeed since still within window
    assert result.is_ok()
    data = result.value
    assert data.status == "verified"

    # Verify updates were made
    mock_uow.users.update.assert_called_once()
    mock_uow.audit_events.create.assert_called_once()
    mock_uow.commit.assert_called_once()
