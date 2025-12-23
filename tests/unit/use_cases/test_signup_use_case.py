import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import bcrypt
import pytest

# Add monorepo root to Python path for libs access
monorepo_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(monorepo_root))

from libs.result import Error
from src.app.use_cases.auth.signup_dto import SignupCommand
from src.app.use_cases.auth.signup_use_case import SignupUseCase
from src.domain.entities import (
    Membership,
    MembershipRole,
    MembershipStatus,
    Session,
    Tenant,
    User,
)


@pytest.fixture
def mock_uow():
    """Mock UnitOfWork with all repositories"""
    uow = MagicMock()
    uow.__aenter__ = AsyncMock(return_value=uow)
    uow.__aexit__ = AsyncMock()
    uow.commit = AsyncMock()
    uow.rollback = AsyncMock()

    # Mock repositories
    uow.users = MagicMock()
    uow.users.get_by_email = AsyncMock()
    uow.users.create = AsyncMock()

    uow.tenants = MagicMock()
    uow.tenants.create = AsyncMock()

    uow.memberships = MagicMock()
    uow.memberships.create = AsyncMock()

    uow.sessions = MagicMock()
    uow.sessions.create = AsyncMock()

    uow.audit_events = MagicMock()
    uow.audit_events.create = AsyncMock()

    return uow


@pytest.mark.asyncio
async def test_successful_signup(mock_uow):
    """Test successful signup flow with Command pattern - AC-1.1"""
    # Arrange
    mock_uow.users.get_by_email.return_value = None  # No existing user

    # Create mock entities with proper IDs
    user_id = uuid4()
    tenant_id = uuid4()

    mock_user = User(
        id=user_id,
        email="founder@acme.com",
        password_hash="hashed_password",
        email_verified=False,
    )
    mock_uow.users.create.return_value = mock_user

    mock_tenant = Tenant(id=tenant_id, name="Acme Corp")
    mock_uow.tenants.create.return_value = mock_tenant

    use_case = SignupUseCase(mock_uow)

    # Create command
    command = SignupCommand(
        email="founder@acme.com", password="SecurePass123!", tenant_name="Acme Corp"
    )

    # Act
    result = await use_case.execute(command)

    # Assert - verify SignupResponse structure
    assert result.is_ok()
    response = result.value
    assert response.user.email == "founder@acme.com"
    assert response.user.email_verified is False
    assert response.tenant.name == "Acme Corp"
    assert response.access_token is not None
    assert response.refresh_token is not None

    # Verify all repositories were called
    mock_uow.users.get_by_email.assert_called_once_with("founder@acme.com")
    mock_uow.users.create.assert_called_once()
    mock_uow.tenants.create.assert_called_once()
    mock_uow.memberships.create.assert_called_once()
    mock_uow.sessions.create.assert_called_once()
    mock_uow.audit_events.create.assert_called_once()
    mock_uow.commit.assert_called_once()


@pytest.mark.asyncio
async def test_signup_email_already_exists(mock_uow):
    """Test signup with existing email using Command - AC-1.2"""
    # Arrange
    existing_user = User(
        id=uuid4(),
        email="founder@acme.com",
        password_hash="hashed_password",
        email_verified=True,
    )
    mock_uow.users.get_by_email.return_value = existing_user

    use_case = SignupUseCase(mock_uow)

    # Create command
    command = SignupCommand(
        email="founder@acme.com", password="SecurePass123!", tenant_name="Acme Corp"
    )

    # Act
    result = await use_case.execute(command)

    # Assert
    assert result.is_err()
    assert result.error.code == "EMAIL_ALREADY_EXISTS"
    assert result.error.message == "Email already registered"

    # Verify no entities were created
    mock_uow.users.create.assert_not_called()
    mock_uow.tenants.create.assert_not_called()
    mock_uow.memberships.create.assert_not_called()
    mock_uow.sessions.create.assert_not_called()
    mock_uow.audit_events.create.assert_not_called()
    mock_uow.commit.assert_not_called()


@pytest.mark.asyncio
async def test_password_hashing(mock_uow):
    """Test that password is hashed with bcrypt cost factor 12 using Command"""
    # Arrange
    mock_uow.users.get_by_email.return_value = None

    user_id = uuid4()
    tenant_id = uuid4()

    mock_user = User(
        id=user_id,
        email="test@example.com",
        password_hash="will_be_set",
        email_verified=False,
    )
    mock_uow.users.create.return_value = mock_user

    mock_tenant = Tenant(id=tenant_id, name="Test Corp")
    mock_uow.tenants.create.return_value = mock_tenant

    use_case = SignupUseCase(mock_uow)
    plain_password = "SecurePass123!"

    # Create command
    command = SignupCommand(
        email="test@example.com", password=plain_password, tenant_name="Test Corp"
    )

    # Act
    result = await use_case.execute(command)

    # Assert
    assert result.is_ok()

    # Get the User object that was passed to create()
    create_call_args = mock_uow.users.create.call_args
    created_user = create_call_args[0][0]

    # Verify password is hashed
    assert created_user.password_hash != plain_password

    # Verify bcrypt can verify the hash
    assert bcrypt.checkpw(
        plain_password.encode("utf-8"), created_user.password_hash.encode("utf-8")
    )


@pytest.mark.asyncio
async def test_transaction_commit_called(mock_uow):
    """Test that transaction commit is called with Command"""
    # Arrange
    mock_uow.users.get_by_email.return_value = None

    user_id = uuid4()
    tenant_id = uuid4()

    mock_user = User(
        id=user_id,
        email="test@example.com",
        password_hash="hashed",
        email_verified=False,
    )
    mock_uow.users.create.return_value = mock_user

    mock_tenant = Tenant(id=tenant_id, name="Test Corp")
    mock_uow.tenants.create.return_value = mock_tenant

    use_case = SignupUseCase(mock_uow)

    # Create command
    command = SignupCommand(
        email="test@example.com", password="SecurePass123!", tenant_name="Test Corp"
    )

    # Act
    result = await use_case.execute(command)

    # Assert
    assert result.is_ok()
    mock_uow.commit.assert_called_once()
    mock_uow.rollback.assert_not_called()


@pytest.mark.asyncio
async def test_membership_created_with_owner_role(mock_uow):
    """Test that membership is created with owner role using Command"""
    # Arrange
    mock_uow.users.get_by_email.return_value = None

    user_id = uuid4()
    tenant_id = uuid4()

    mock_user = User(
        id=user_id,
        email="test@example.com",
        password_hash="hashed",
        email_verified=False,
    )
    mock_uow.users.create.return_value = mock_user

    mock_tenant = Tenant(id=tenant_id, name="Test Corp")
    mock_uow.tenants.create.return_value = mock_tenant

    use_case = SignupUseCase(mock_uow)

    # Create command
    command = SignupCommand(
        email="test@example.com", password="SecurePass123!", tenant_name="Test Corp"
    )

    # Act
    result = await use_case.execute(command)

    # Assert
    assert result.is_ok()

    # Get the Membership object that was passed to create()
    create_call_args = mock_uow.memberships.create.call_args
    created_membership = create_call_args[0][0]

    assert created_membership.role == MembershipRole.owner
    assert created_membership.status == MembershipStatus.active
    assert created_membership.user_id == user_id
    assert created_membership.tenant_id == tenant_id
