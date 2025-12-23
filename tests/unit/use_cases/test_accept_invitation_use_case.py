import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4
from datetime import datetime, timedelta

import pytest
import bcrypt

# Add monorepo root to Python path for libs access
monorepo_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(monorepo_root))

from libs.result import Error
from src.app.use_cases.tenants.accept_invitation_use_case import (
    AcceptInvitationUseCase,
)
from src.domain.entities import (
    Invitation,
    InvitationStatus,
    Membership,
    MembershipRole,
    MembershipStatus,
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
    uow.invitations = MagicMock()
    uow.invitations.get_by_token = AsyncMock()
    uow.invitations.update = AsyncMock()

    uow.tenants = MagicMock()
    uow.tenants.get_by_id = AsyncMock()

    uow.users = MagicMock()
    uow.users.get_by_email = AsyncMock()
    uow.users.create = AsyncMock()
    uow.users.update = AsyncMock()

    uow.memberships = MagicMock()
    uow.memberships.get_by_user_and_tenant = AsyncMock()
    uow.memberships.create = AsyncMock()

    uow.sessions = MagicMock()
    uow.sessions.create = AsyncMock()

    uow.audit_events = MagicMock()
    uow.audit_events.create = AsyncMock()

    return uow


@pytest.mark.asyncio
async def test_successful_acceptance_existing_user(mock_uow):
    """Test AC-14.1: Existing user accepts invitation"""
    # Arrange
    token = "valid_invitation_token"
    tenant_id = uuid4()
    user_id = uuid4()
    email = "existing@example.com"

    # Mock invitation
    invitation = Invitation(
        id=uuid4(),
        tenant_id=tenant_id,
        email=email,
        role=MembershipRole.member,
        status=InvitationStatus.pending,
        expires_at=datetime.utcnow() + timedelta(days=7),
        token=token,
    )
    mock_uow.invitations.get_by_token.return_value = invitation

    # Mock tenant
    tenant = Tenant(id=tenant_id, name="Acme Corp", owner_id=uuid4())
    mock_uow.tenants.get_by_id.return_value = tenant

    # Mock existing user
    existing_user = User(
        id=user_id,
        email=email,
        password_hash="hashed_password",
        email_verified=True,
    )
    mock_uow.users.get_by_email.return_value = existing_user

    # No existing membership
    mock_uow.memberships.get_by_user_and_tenant.return_value = None

    # Mock returns for create operations
    def create_membership_side_effect(membership):
        membership.id = uuid4()
        return membership

    mock_uow.memberships.create.side_effect = create_membership_side_effect

    # Act
    use_case = AcceptInvitationUseCase(mock_uow)
    result = await use_case.execute(token)

    # Assert
    assert result.is_ok()
    response = result.value

    # Verify response structure
    assert response.access_token is not None
    assert response.refresh_token is not None
    assert response.tenant.id == str(tenant_id)
    assert response.tenant.name == "Acme Corp"
    assert response.tenant.role == "member"
    assert response.email_verification_required is False  # Already verified

    # Verify invitation was marked as accepted
    assert invitation.status == InvitationStatus.accepted

    # Verify membership was created
    mock_uow.memberships.create.assert_called_once()
    created_membership = mock_uow.memberships.create.call_args[0][0]
    assert created_membership.user_id == user_id
    assert created_membership.tenant_id == tenant_id
    assert created_membership.role == MembershipRole.member
    assert created_membership.status == MembershipStatus.active

    # Verify session was created
    mock_uow.sessions.create.assert_called_once()

    # Verify audit event was created
    mock_uow.audit_events.create.assert_called_once()
    audit_event = mock_uow.audit_events.create.call_args[0][0]
    assert audit_event.action == "invitation_accepted"
    assert audit_event.event_metadata["is_new_user"] is False

    # Verify user's last_active_tenant_id was updated
    mock_uow.users.update.assert_called_once()

    # Verify transaction was committed
    mock_uow.commit.assert_called_once()


@pytest.mark.asyncio
async def test_successful_acceptance_new_user(mock_uow):
    """Test AC-14.2: New user accepts invitation with password"""
    # Arrange
    token = "valid_invitation_token"
    password = "SecurePass123!"
    tenant_id = uuid4()
    email = "newuser@example.com"

    # Mock invitation
    invitation = Invitation(
        id=uuid4(),
        tenant_id=tenant_id,
        email=email,
        role=MembershipRole.member,
        status=InvitationStatus.pending,
        expires_at=datetime.utcnow() + timedelta(days=7),
        token=token,
    )
    mock_uow.invitations.get_by_token.return_value = invitation

    # Mock tenant
    tenant = Tenant(id=tenant_id, name="Acme Corp", owner_id=uuid4())
    mock_uow.tenants.get_by_id.return_value = tenant

    # No existing user
    mock_uow.users.get_by_email.return_value = None

    # Mock user creation
    def create_user_side_effect(user):
        user.id = uuid4()
        return user

    mock_uow.users.create.side_effect = create_user_side_effect

    # Mock membership creation
    def create_membership_side_effect(membership):
        membership.id = uuid4()
        return membership

    mock_uow.memberships.create.side_effect = create_membership_side_effect

    # Act
    use_case = AcceptInvitationUseCase(mock_uow)
    result = await use_case.execute(token, password)

    # Assert
    assert result.is_ok()
    response = result.value

    # Verify response
    assert response.access_token is not None
    assert response.refresh_token is not None
    assert response.tenant.id == str(tenant_id)
    assert response.tenant.name == "Acme Corp"
    assert response.tenant.role == "member"
    assert response.email_verification_required is True  # New user not verified

    # Verify user was created
    mock_uow.users.create.assert_called_once()
    created_user = mock_uow.users.create.call_args[0][0]
    assert created_user.email == email
    assert created_user.email_verified is False
    assert bcrypt.checkpw(password.encode("utf-8"), created_user.password_hash.encode("utf-8"))

    # Verify membership was created
    mock_uow.memberships.create.assert_called_once()

    # Verify audit event indicates new user
    audit_event = mock_uow.audit_events.create.call_args[0][0]
    assert audit_event.event_metadata["is_new_user"] is True


@pytest.mark.asyncio
async def test_expired_invitation(mock_uow):
    """Test AC-14.3: Expired invitation is rejected"""
    # Arrange
    token = "expired_invitation_token"

    # Mock expired invitation
    invitation = Invitation(
        id=uuid4(),
        tenant_id=uuid4(),
        email="user@example.com",
        role=MembershipRole.member,
        status=InvitationStatus.pending,
        expires_at=datetime.utcnow() - timedelta(hours=1),  # Expired 1 hour ago
        token=token,
    )
    mock_uow.invitations.get_by_token.return_value = invitation

    # Act
    use_case = AcceptInvitationUseCase(mock_uow)
    result = await use_case.execute(token)

    # Assert
    assert result.is_err()
    assert result.error.code == "INVITATION_EXPIRED"
    assert "expired" in result.error.message.lower()

    # Verify invitation status was updated to expired
    assert invitation.status == InvitationStatus.expired
    mock_uow.invitations.update.assert_called_once_with(invitation)
    mock_uow.commit.assert_called_once()


@pytest.mark.asyncio
async def test_already_accepted_invitation(mock_uow):
    """Test AC-14.4: Already accepted invitation is rejected"""
    # Arrange
    token = "already_accepted_token"

    # Mock already accepted invitation
    invitation = Invitation(
        id=uuid4(),
        tenant_id=uuid4(),
        email="user@example.com",
        role=MembershipRole.member,
        status=InvitationStatus.accepted,  # Already accepted
        expires_at=datetime.utcnow() + timedelta(days=7),
        token=token,
    )
    mock_uow.invitations.get_by_token.return_value = invitation

    # Act
    use_case = AcceptInvitationUseCase(mock_uow)
    result = await use_case.execute(token)

    # Assert
    assert result.is_err()
    assert result.error.code == "INVITATION_ALREADY_ACCEPTED"
    assert "already been accepted" in result.error.message.lower()


@pytest.mark.asyncio
async def test_invalid_token(mock_uow):
    """Test invalid or non-existent invitation token"""
    # Arrange
    token = "invalid_token"

    # No invitation found
    mock_uow.invitations.get_by_token.return_value = None

    # Act
    use_case = AcceptInvitationUseCase(mock_uow)
    result = await use_case.execute(token)

    # Assert
    assert result.is_err()
    assert result.error.code == "INVALID_TOKEN"


@pytest.mark.asyncio
async def test_password_required_for_new_user(mock_uow):
    """Test that password is required for new users"""
    # Arrange
    token = "valid_token"
    tenant_id = uuid4()
    email = "newuser@example.com"

    # Mock invitation
    invitation = Invitation(
        id=uuid4(),
        tenant_id=tenant_id,
        email=email,
        role=MembershipRole.member,
        status=InvitationStatus.pending,
        expires_at=datetime.utcnow() + timedelta(days=7),
        token=token,
    )
    mock_uow.invitations.get_by_token.return_value = invitation

    # Mock tenant
    tenant = Tenant(id=tenant_id, name="Acme Corp", owner_id=uuid4())
    mock_uow.tenants.get_by_id.return_value = tenant

    # No existing user
    mock_uow.users.get_by_email.return_value = None

    # Act - no password provided
    use_case = AcceptInvitationUseCase(mock_uow)
    result = await use_case.execute(token)

    # Assert
    assert result.is_err()
    assert result.error.code == "PASSWORD_REQUIRED"


@pytest.mark.asyncio
async def test_password_too_short(mock_uow):
    """Test that password must be at least 8 characters"""
    # Arrange
    token = "valid_token"
    password = "short"  # Only 5 characters
    tenant_id = uuid4()
    email = "newuser@example.com"

    # Mock invitation
    invitation = Invitation(
        id=uuid4(),
        tenant_id=tenant_id,
        email=email,
        role=MembershipRole.member,
        status=InvitationStatus.pending,
        expires_at=datetime.utcnow() + timedelta(days=7),
        token=token,
    )
    mock_uow.invitations.get_by_token.return_value = invitation

    # Mock tenant
    tenant = Tenant(id=tenant_id, name="Acme Corp", owner_id=uuid4())
    mock_uow.tenants.get_by_id.return_value = tenant

    # No existing user
    mock_uow.users.get_by_email.return_value = None

    # Act
    use_case = AcceptInvitationUseCase(mock_uow)
    result = await use_case.execute(token, password)

    # Assert
    assert result.is_err()
    assert result.error.code == "INVALID_PASSWORD"
    assert "8 characters" in result.error.message


@pytest.mark.asyncio
async def test_user_already_member(mock_uow):
    """Test that user cannot accept invitation if already an active member"""
    # Arrange
    token = "valid_token"
    tenant_id = uuid4()
    user_id = uuid4()
    email = "existing@example.com"

    # Mock invitation
    invitation = Invitation(
        id=uuid4(),
        tenant_id=tenant_id,
        email=email,
        role=MembershipRole.member,
        status=InvitationStatus.pending,
        expires_at=datetime.utcnow() + timedelta(days=7),
        token=token,
    )
    mock_uow.invitations.get_by_token.return_value = invitation

    # Mock tenant
    tenant = Tenant(id=tenant_id, name="Acme Corp", owner_id=uuid4())
    mock_uow.tenants.get_by_id.return_value = tenant

    # Mock existing user
    existing_user = User(
        id=user_id,
        email=email,
        password_hash="hashed_password",
        email_verified=True,
    )
    mock_uow.users.get_by_email.return_value = existing_user

    # Mock existing active membership
    existing_membership = Membership(
        id=uuid4(),
        user_id=user_id,
        tenant_id=tenant_id,
        role=MembershipRole.member,
        status=MembershipStatus.active,
    )
    mock_uow.memberships.get_by_user_and_tenant.return_value = existing_membership

    # Act
    use_case = AcceptInvitationUseCase(mock_uow)
    result = await use_case.execute(token)

    # Assert
    assert result.is_err()
    assert result.error.code == "ALREADY_MEMBER"


@pytest.mark.asyncio
async def test_tenant_not_found(mock_uow):
    """Test error when tenant doesn't exist"""
    # Arrange
    token = "valid_token"

    # Mock invitation
    invitation = Invitation(
        id=uuid4(),
        tenant_id=uuid4(),
        email="user@example.com",
        role=MembershipRole.member,
        status=InvitationStatus.pending,
        expires_at=datetime.utcnow() + timedelta(days=7),
        token=token,
    )
    mock_uow.invitations.get_by_token.return_value = invitation

    # Tenant not found
    mock_uow.tenants.get_by_id.return_value = None

    # Act
    use_case = AcceptInvitationUseCase(mock_uow)
    result = await use_case.execute(token)

    # Assert
    assert result.is_err()
    assert result.error.code == "TENANT_NOT_FOUND"


@pytest.mark.asyncio
async def test_password_is_hashed_with_bcrypt(mock_uow):
    """Test that password is hashed using bcrypt for new users"""
    # Arrange
    token = "valid_token"
    password = "PlainTextPassword123!"
    tenant_id = uuid4()
    email = "newuser@example.com"

    # Mock invitation
    invitation = Invitation(
        id=uuid4(),
        tenant_id=tenant_id,
        email=email,
        role=MembershipRole.member,
        status=InvitationStatus.pending,
        expires_at=datetime.utcnow() + timedelta(days=7),
        token=token,
    )
    mock_uow.invitations.get_by_token.return_value = invitation

    # Mock tenant
    tenant = Tenant(id=tenant_id, name="Acme Corp", owner_id=uuid4())
    mock_uow.tenants.get_by_id.return_value = tenant

    # No existing user
    mock_uow.users.get_by_email.return_value = None

    # Mock user creation
    def create_user_side_effect(user):
        user.id = uuid4()
        return user

    mock_uow.users.create.side_effect = create_user_side_effect

    # Mock membership creation
    def create_membership_side_effect(membership):
        membership.id = uuid4()
        return membership

    mock_uow.memberships.create.side_effect = create_membership_side_effect

    # Act
    use_case = AcceptInvitationUseCase(mock_uow)
    result = await use_case.execute(token, password)

    # Assert
    assert result.is_ok()

    # Verify password was hashed
    created_user = mock_uow.users.create.call_args[0][0]
    assert created_user.password_hash != password
    assert bcrypt.checkpw(password.encode("utf-8"), created_user.password_hash.encode("utf-8"))


@pytest.mark.asyncio
async def test_session_created_with_refresh_token(mock_uow):
    """Test that session is created with hashed refresh token"""
    # Arrange
    token = "valid_token"
    tenant_id = uuid4()
    user_id = uuid4()
    email = "user@example.com"

    # Mock invitation
    invitation = Invitation(
        id=uuid4(),
        tenant_id=tenant_id,
        email=email,
        role=MembershipRole.admin,
        status=InvitationStatus.pending,
        expires_at=datetime.utcnow() + timedelta(days=7),
        token=token,
    )
    mock_uow.invitations.get_by_token.return_value = invitation

    # Mock tenant
    tenant = Tenant(id=tenant_id, name="Acme Corp", owner_id=uuid4())
    mock_uow.tenants.get_by_id.return_value = tenant

    # Mock existing user
    existing_user = User(
        id=user_id,
        email=email,
        password_hash="hashed_password",
        email_verified=True,
    )
    mock_uow.users.get_by_email.return_value = existing_user

    # No existing membership
    mock_uow.memberships.get_by_user_and_tenant.return_value = None

    # Mock membership creation
    def create_membership_side_effect(membership):
        membership.id = uuid4()
        return membership

    mock_uow.memberships.create.side_effect = create_membership_side_effect

    # Act
    use_case = AcceptInvitationUseCase(mock_uow)
    result = await use_case.execute(token)

    # Assert
    assert result.is_ok()

    # Verify session was created
    mock_uow.sessions.create.assert_called_once()
    created_session = mock_uow.sessions.create.call_args[0][0]
    assert created_session.user_id == user_id
    assert created_session.tenant_id == tenant_id
    assert created_session.refresh_token_hash is not None

    # Verify refresh token is hashed (should be bcrypt hash)
    assert len(created_session.refresh_token_hash) == 60  # bcrypt hash length
    assert created_session.refresh_token_hash.startswith("$2b$")


@pytest.mark.asyncio
async def test_audit_event_created_with_metadata(mock_uow):
    """Test that audit event is created with correct metadata"""
    # Arrange
    token = "valid_token"
    tenant_id = uuid4()
    user_id = uuid4()
    email = "user@example.com"
    invitation_id = uuid4()

    # Mock invitation
    invitation = Invitation(
        id=invitation_id,
        tenant_id=tenant_id,
        email=email,
        role=MembershipRole.member,
        status=InvitationStatus.pending,
        expires_at=datetime.utcnow() + timedelta(days=7),
        token=token,
    )
    mock_uow.invitations.get_by_token.return_value = invitation

    # Mock tenant
    tenant = Tenant(id=tenant_id, name="Acme Corp", owner_id=uuid4())
    mock_uow.tenants.get_by_id.return_value = tenant

    # Mock existing user
    existing_user = User(
        id=user_id,
        email=email,
        password_hash="hashed_password",
        email_verified=True,
    )
    mock_uow.users.get_by_email.return_value = existing_user

    # No existing membership
    mock_uow.memberships.get_by_user_and_tenant.return_value = None

    # Mock membership creation
    def create_membership_side_effect(membership):
        membership.id = uuid4()
        return membership

    mock_uow.memberships.create.side_effect = create_membership_side_effect

    # Act
    use_case = AcceptInvitationUseCase(mock_uow)
    result = await use_case.execute(token)

    # Assert
    assert result.is_ok()

    # Verify audit event
    mock_uow.audit_events.create.assert_called_once()
    audit_event = mock_uow.audit_events.create.call_args[0][0]
    assert audit_event.tenant_id == tenant_id
    assert audit_event.user_id == user_id
    assert audit_event.action == "invitation_accepted"
    assert audit_event.event_metadata["invitation_id"] == str(invitation_id)
    assert audit_event.event_metadata["is_new_user"] is False
    assert audit_event.event_metadata["role"] == "member"


@pytest.mark.asyncio
async def test_last_active_tenant_updated(mock_uow):
    """Test that user's last_active_tenant_id is updated"""
    # Arrange
    token = "valid_token"
    tenant_id = uuid4()
    user_id = uuid4()
    email = "user@example.com"

    # Mock invitation
    invitation = Invitation(
        id=uuid4(),
        tenant_id=tenant_id,
        email=email,
        role=MembershipRole.member,
        status=InvitationStatus.pending,
        expires_at=datetime.utcnow() + timedelta(days=7),
        token=token,
    )
    mock_uow.invitations.get_by_token.return_value = invitation

    # Mock tenant
    tenant = Tenant(id=tenant_id, name="Acme Corp", owner_id=uuid4())
    mock_uow.tenants.get_by_id.return_value = tenant

    # Mock existing user
    existing_user = User(
        id=user_id,
        email=email,
        password_hash="hashed_password",
        email_verified=True,
        last_active_tenant_id=None,  # No last active tenant
    )
    mock_uow.users.get_by_email.return_value = existing_user

    # No existing membership
    mock_uow.memberships.get_by_user_and_tenant.return_value = None

    # Mock membership creation
    def create_membership_side_effect(membership):
        membership.id = uuid4()
        return membership

    mock_uow.memberships.create.side_effect = create_membership_side_effect

    # Act
    use_case = AcceptInvitationUseCase(mock_uow)
    result = await use_case.execute(token)

    # Assert
    assert result.is_ok()

    # Verify user's last_active_tenant_id was updated
    mock_uow.users.update.assert_called_once()
    updated_user = mock_uow.users.update.call_args[0][0]
    assert updated_user.last_active_tenant_id == tenant_id
