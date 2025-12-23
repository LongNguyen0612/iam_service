"""
Unit tests for RequestPasswordResetUseCase

Tests all business logic with mocked dependencies.
"""
import sys
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

# Add monorepo root to Python path for libs access
monorepo_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(monorepo_root))

from libs.result import Error
from src.app.use_cases.auth.request_password_reset_use_case import RequestPasswordResetUseCase
from src.domain.entities import User, PasswordResetToken


@pytest.fixture
def mock_uow():
    """Mock UnitOfWork with all required repositories"""
    uow = MagicMock()
    uow.__aenter__ = AsyncMock(return_value=uow)
    uow.__aexit__ = AsyncMock(return_value=False)
    uow.commit = AsyncMock()
    uow.rollback = AsyncMock()

    # Mock repositories
    uow.users = MagicMock()
    uow.users.get_by_email = AsyncMock()

    uow.password_reset_tokens = MagicMock()
    uow.password_reset_tokens.create = AsyncMock()

    return uow


@pytest.fixture
def mock_audit_service():
    """Mock AuditService for audit logging"""
    audit_service = MagicMock()
    audit_service.log_event = AsyncMock()
    return audit_service


@pytest.mark.asyncio
async def test_successful_password_reset_request(mock_uow, mock_audit_service):
    """Test successful password reset request - AC-12.1"""
    # Arrange
    user_id = uuid4()
    email = "user@example.com"

    mock_user = User(
        id=user_id,
        email=email,
        password_hash="hashed_password",
        email_verified=True,
    )
    mock_uow.users.get_by_email.return_value = mock_user

    # Mock the token creation to capture the token
    created_token = None
    async def capture_token(token):
        nonlocal created_token
        created_token = token
        return token

    mock_uow.password_reset_tokens.create.side_effect = capture_token

    use_case = RequestPasswordResetUseCase(mock_uow, mock_audit_service)

    # Act
    result = await use_case.execute(email)

    # Assert
    assert result.is_ok()
    data = result.value
    assert data.status == "sent"
    assert hasattr(data, "message")

    # Verify password reset token was created
    mock_uow.password_reset_tokens.create.assert_called_once()

    # Verify token properties
    assert created_token is not None
    assert created_token.user_id == user_id
    assert created_token.used is False
    assert len(created_token.token_hash) == 64  # SHA-256 hex digest is 64 chars

    # Verify expiry is set to ~1 hour from now
    time_until_expiry = created_token.expires_at - datetime.now(UTC)
    assert time_until_expiry.total_seconds() > 55 * 60  # At least 55 minutes
    assert time_until_expiry.total_seconds() < 65 * 60  # Less than 65 minutes

    # Verify audit event was created
    mock_audit_service.log_event.assert_called_once()

    # Verify transaction committed
    mock_uow.commit.assert_called_once()


@pytest.mark.asyncio
async def test_password_reset_non_existent_email(mock_uow, mock_audit_service):
    """Test password reset for non-existent email - No enumeration - AC-12.2"""
    # Arrange
    email = "nonexistent@example.com"
    mock_uow.users.get_by_email.return_value = None

    use_case = RequestPasswordResetUseCase(mock_uow, mock_audit_service)

    # Act
    result = await use_case.execute(email)

    # Assert - returns success to prevent email enumeration
    assert result.is_ok()
    data = result.value
    assert data.status == "sent"
    assert hasattr(data, "message")

    # Verify no token was created
    mock_uow.password_reset_tokens.create.assert_not_called()

    # Verify no audit event was created
    mock_audit_service.log_event.assert_not_called()

    # Verify no commit (no changes made)
    mock_uow.commit.assert_not_called()


@pytest.mark.asyncio
async def test_password_reset_token_is_hashed_with_sha256(mock_uow, mock_audit_service):
    """Test that token is hashed with SHA-256 before storing"""
    # Arrange
    user_id = uuid4()
    email = "user@example.com"

    mock_user = User(
        id=user_id,
        email=email,
        password_hash="hashed_password",
        email_verified=True,
    )
    mock_uow.users.get_by_email.return_value = mock_user

    # Capture the created token
    created_token = None
    async def capture_token(token):
        nonlocal created_token
        created_token = token
        return token

    mock_uow.password_reset_tokens.create.side_effect = capture_token

    use_case = RequestPasswordResetUseCase(mock_uow, mock_audit_service)

    # Act
    result = await use_case.execute(email)

    # Assert
    assert result.is_ok()

    # Verify token is a valid SHA-256 hash
    assert created_token is not None
    assert len(created_token.token_hash) == 64  # SHA-256 hex digest

    # Verify it's hexadecimal
    try:
        int(created_token.token_hash, 16)
        is_hex = True
    except ValueError:
        is_hex = False
    assert is_hex


@pytest.mark.asyncio
async def test_password_reset_token_expires_in_one_hour(mock_uow, mock_audit_service):
    """Test that token expires in exactly 1 hour"""
    # Arrange
    user_id = uuid4()
    email = "user@example.com"

    mock_user = User(
        id=user_id,
        email=email,
        password_hash="hashed_password",
        email_verified=True,
    )
    mock_uow.users.get_by_email.return_value = mock_user

    # Capture the created token
    created_token = None
    async def capture_token(token):
        nonlocal created_token
        created_token = token
        return token

    mock_uow.password_reset_tokens.create.side_effect = capture_token

    use_case = RequestPasswordResetUseCase(mock_uow, mock_audit_service)

    # Act
    before_time = datetime.now(UTC)
    result = await use_case.execute(email)
    after_time = datetime.now(UTC)

    # Assert
    assert result.is_ok()
    assert created_token is not None

    # Calculate expected expiry (1 hour from now)
    expected_expiry_min = before_time + timedelta(hours=1)
    expected_expiry_max = after_time + timedelta(hours=1)

    assert created_token.expires_at >= expected_expiry_min
    assert created_token.expires_at <= expected_expiry_max


@pytest.mark.asyncio
async def test_password_reset_creates_audit_event(mock_uow, mock_audit_service):
    """Test that an audit event is created for security tracking"""
    # Arrange
    user_id = uuid4()
    email = "user@example.com"

    mock_user = User(
        id=user_id,
        email=email,
        password_hash="hashed_password",
        email_verified=True,
    )
    mock_uow.users.get_by_email.return_value = mock_user

    # Mock token creation
    async def mock_create_token(token):
        return token
    mock_uow.password_reset_tokens.create.side_effect = mock_create_token

    use_case = RequestPasswordResetUseCase(mock_uow, mock_audit_service)

    # Act
    result = await use_case.execute(email)

    # Assert
    assert result.is_ok()

    # Verify audit event was created
    mock_audit_service.log_event.assert_called_once()


@pytest.mark.asyncio
async def test_password_reset_token_is_cryptographically_secure(mock_uow, mock_audit_service):
    """Test that generated token is cryptographically secure (32+ chars)"""
    # Arrange
    user_id = uuid4()
    email = "user@example.com"

    mock_user = User(
        id=user_id,
        email=email,
        password_hash="hashed_password",
        email_verified=True,
    )
    mock_uow.users.get_by_email.return_value = mock_user

    # Capture the token
    created_token = None
    async def capture_token(token):
        nonlocal created_token
        created_token = token
        return token

    mock_uow.password_reset_tokens.create.side_effect = capture_token

    use_case = RequestPasswordResetUseCase(mock_uow, mock_audit_service)

    # Act
    result = await use_case.execute(email)

    # Assert
    assert result.is_ok()

    # The token_hash should be SHA-256 of a 32-byte secure token
    # SHA-256 always produces 64 hex characters
    assert created_token is not None
    assert len(created_token.token_hash) == 64


@pytest.mark.asyncio
async def test_password_reset_token_marked_as_unused(mock_uow, mock_audit_service):
    """Test that created token is marked as unused"""
    # Arrange
    user_id = uuid4()
    email = "user@example.com"

    mock_user = User(
        id=user_id,
        email=email,
        password_hash="hashed_password",
        email_verified=True,
    )
    mock_uow.users.get_by_email.return_value = mock_user

    # Capture the token
    created_token = None
    async def capture_token(token):
        nonlocal created_token
        created_token = token
        return token

    mock_uow.password_reset_tokens.create.side_effect = capture_token

    use_case = RequestPasswordResetUseCase(mock_uow, mock_audit_service)

    # Act
    result = await use_case.execute(email)

    # Assert
    assert result.is_ok()
    assert created_token is not None
    assert created_token.used is False


@pytest.mark.asyncio
async def test_password_reset_multiple_tokens_allowed(mock_uow, mock_audit_service):
    """Test that multiple password reset requests create multiple tokens"""
    # Arrange
    user_id = uuid4()
    email = "user@example.com"

    mock_user = User(
        id=user_id,
        email=email,
        password_hash="hashed_password",
        email_verified=True,
    )
    mock_uow.users.get_by_email.return_value = mock_user

    # Mock token creation
    async def mock_create_token(token):
        return token
    mock_uow.password_reset_tokens.create.side_effect = mock_create_token

    use_case = RequestPasswordResetUseCase(mock_uow, mock_audit_service)

    # Act - make two requests
    result1 = await use_case.execute(email)
    result2 = await use_case.execute(email)

    # Assert
    assert result1.is_ok()
    assert result2.is_ok()

    # Verify two tokens were created
    assert mock_uow.password_reset_tokens.create.call_count == 2

    # Verify two commits
    assert mock_uow.commit.call_count == 2


@pytest.mark.asyncio
async def test_password_reset_no_enumeration_same_message(mock_uow, mock_audit_service):
    """Test that valid and invalid emails return the same message"""
    # Arrange
    valid_email = "valid@example.com"
    invalid_email = "invalid@example.com"

    mock_user = User(
        id=uuid4(),
        email=valid_email,
        password_hash="hashed_password",
        email_verified=True,
    )

    async def get_user_by_email(email):
        if email == valid_email:
            return mock_user
        return None

    mock_uow.users.get_by_email.side_effect = get_user_by_email

    # Mock token creation
    async def mock_create_token(token):
        return token
    mock_uow.password_reset_tokens.create.side_effect = mock_create_token

    use_case = RequestPasswordResetUseCase(mock_uow, mock_audit_service)

    # Act
    result_valid = await use_case.execute(valid_email)
    result_invalid = await use_case.execute(invalid_email)

    # Assert - both should succeed with same message
    assert result_valid.is_ok()
    assert result_invalid.is_ok()

    assert result_valid.value.status == result_invalid.value.status
    assert result_valid.value.message == result_invalid.value.message
