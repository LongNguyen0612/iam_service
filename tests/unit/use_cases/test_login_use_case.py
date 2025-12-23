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
from src.app.use_cases.auth.login_use_case import LoginUseCase
from src.domain.entities import (
    Membership,
    MembershipRole,
    MembershipStatus,
    Tenant,
    User,
    UserStatus,
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
    uow.users.update = AsyncMock()

    uow.memberships = MagicMock()
    uow.memberships.get_by_user_id = AsyncMock()

    uow.tenants = MagicMock()
    uow.tenants.get_by_id = AsyncMock()

    uow.sessions = MagicMock()
    uow.sessions.create = AsyncMock()

    uow.audit_events = MagicMock()
    uow.audit_events.create = AsyncMock()

    return uow


@pytest.mark.asyncio
async def test_successful_login(mock_uow):
    """Test successful login flow - AC-2.1"""
    # Arrange
    user_id = uuid4()
    tenant_id = uuid4()
    password = "SecurePass123!"
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))

    mock_user = User(
        id=user_id,
        email="user@acme.com",
        password_hash=password_hash.decode(),
        status=UserStatus.active,
    )
    mock_uow.users.get_by_email.return_value = mock_user

    mock_membership = Membership(
        id=uuid4(),
        user_id=user_id,
        tenant_id=tenant_id,
        role=MembershipRole.admin,
        status=MembershipStatus.active,
    )
    mock_uow.memberships.get_by_user_id.return_value = [mock_membership]

    mock_tenant = Tenant(id=tenant_id, name="Acme Corp")
    mock_uow.tenants.get_by_id.return_value = mock_tenant

    use_case = LoginUseCase(mock_uow)

    # Act
    result = await use_case.execute("user@acme.com", password)

    # Assert
    assert result.is_ok()
    data = result.value
    assert hasattr(data, "access_token")
    assert hasattr(data, "refresh_token")
    assert data.active_tenant.name == "Acme Corp"
    assert data.active_tenant.role == "admin"

    # Verify UnitOfWork calls
    mock_uow.users.get_by_email.assert_called_once_with("user@acme.com")
    mock_uow.memberships.get_by_user_id.assert_called_once_with(user_id)
    mock_uow.tenants.get_by_id.assert_called()
    mock_uow.sessions.create.assert_called_once()
    mock_uow.users.update.assert_called_once()
    mock_uow.audit_events.create.assert_called_once()
    mock_uow.commit.assert_called_once()


@pytest.mark.asyncio
async def test_login_invalid_credentials_wrong_password(mock_uow):
    """Test login with wrong password - AC-2.2"""
    # Arrange
    user_id = uuid4()
    password = "SecurePass123!"
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))

    mock_user = User(
        id=user_id,
        email="user@acme.com",
        password_hash=password_hash.decode(),
        status=UserStatus.active,
    )
    mock_uow.users.get_by_email.return_value = mock_user

    use_case = LoginUseCase(mock_uow)

    # Act
    result = await use_case.execute("user@acme.com", "WrongPassword!")

    # Assert
    assert result.is_err()
    assert result.error.code == "INVALID_CREDENTIALS"
    assert result.error.message == "Invalid email or password"

    # Verify no session created
    mock_uow.sessions.create.assert_not_called()
    mock_uow.commit.assert_not_called()


@pytest.mark.asyncio
async def test_login_invalid_credentials_nonexistent_user(mock_uow):
    """Test login with non-existent user - AC-2.2"""
    # Arrange
    mock_uow.users.get_by_email.return_value = None

    use_case = LoginUseCase(mock_uow)

    # Act
    result = await use_case.execute("nonexistent@acme.com", "SomePassword!")

    # Assert
    assert result.is_err()
    assert result.error.code == "INVALID_CREDENTIALS"
    assert result.error.message == "Invalid email or password"

    # Verify no session created
    mock_uow.sessions.create.assert_not_called()
    mock_uow.commit.assert_not_called()


@pytest.mark.asyncio
async def test_login_user_disabled(mock_uow):
    """Test login with disabled user - AC-2.4"""
    # Arrange
    user_id = uuid4()
    password = "SecurePass123!"
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))

    mock_user = User(
        id=user_id,
        email="user@acme.com",
        password_hash=password_hash.decode(),
        status=UserStatus.disabled,
    )
    mock_uow.users.get_by_email.return_value = mock_user

    use_case = LoginUseCase(mock_uow)

    # Act
    result = await use_case.execute("user@acme.com", password)

    # Assert
    assert result.is_err()
    assert result.error.code == "USER_DISABLED"
    assert result.error.message == "User account is disabled"

    # Verify no session created
    mock_uow.sessions.create.assert_not_called()
    mock_uow.commit.assert_not_called()


@pytest.mark.asyncio
async def test_login_no_active_membership(mock_uow):
    """Test login with no active memberships - AC-2.3"""
    # Arrange
    user_id = uuid4()
    tenant_id = uuid4()
    password = "SecurePass123!"
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))

    mock_user = User(
        id=user_id,
        email="user@acme.com",
        password_hash=password_hash.decode(),
        status=UserStatus.active,
    )
    mock_uow.users.get_by_email.return_value = mock_user

    # All memberships are revoked
    mock_membership = Membership(
        id=uuid4(),
        user_id=user_id,
        tenant_id=tenant_id,
        role=MembershipRole.member,
        status=MembershipStatus.revoked,
    )
    mock_uow.memberships.get_by_user_id.return_value = [mock_membership]

    use_case = LoginUseCase(mock_uow)

    # Act
    result = await use_case.execute("user@acme.com", password)

    # Assert
    assert result.is_err()
    assert result.error.code == "NO_ACTIVE_MEMBERSHIP"
    assert result.error.message == "User has no active tenant memberships"

    # Verify no session created
    mock_uow.sessions.create.assert_not_called()
    mock_uow.commit.assert_not_called()


@pytest.mark.asyncio
async def test_login_default_tenant_selection(mock_uow):
    """Test login with multiple memberships - uses last_active_tenant_id - AC-2.5"""
    # Arrange
    user_id = uuid4()
    tenant1_id = uuid4()
    tenant2_id = uuid4()
    password = "SecurePass123!"
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))

    mock_user = User(
        id=user_id,
        email="user@acme.com",
        password_hash=password_hash.decode(),
        status=UserStatus.active,
        last_active_tenant_id=tenant2_id,
    )
    mock_uow.users.get_by_email.return_value = mock_user

    # Multiple memberships
    mock_membership1 = Membership(
        id=uuid4(),
        user_id=user_id,
        tenant_id=tenant1_id,
        role=MembershipRole.owner,
        status=MembershipStatus.active,
    )
    mock_membership2 = Membership(
        id=uuid4(),
        user_id=user_id,
        tenant_id=tenant2_id,
        role=MembershipRole.admin,
        status=MembershipStatus.active,
    )
    mock_uow.memberships.get_by_user_id.return_value = [
        mock_membership1,
        mock_membership2,
    ]

    mock_tenant2 = Tenant(id=tenant2_id, name="Last Active Corp")
    mock_uow.tenants.get_by_id.return_value = mock_tenant2

    use_case = LoginUseCase(mock_uow)

    # Act
    result = await use_case.execute("user@acme.com", password)

    # Assert
    assert result.is_ok()
    data = result.value
    assert data.active_tenant.id == str(tenant2_id)
    assert data.active_tenant.name == "Last Active Corp"
    assert data.active_tenant.role == "admin"

    # Verify commit was called
    mock_uow.commit.assert_called_once()
