import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

# Add monorepo root to Python path for libs access
monorepo_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(monorepo_root))

from libs.result import Error
from src.app.use_cases.tenants.invite_user_use_case import InviteUserUseCase
from src.domain.entities import (
    Invitation,
    InvitationStatus,
    Membership,
    MembershipRole,
    MembershipStatus,
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

    uow.memberships = MagicMock()
    uow.memberships.get_by_user_and_tenant = AsyncMock()

    uow.invitations = MagicMock()
    uow.invitations.get_pending_by_tenant_and_email = AsyncMock()
    uow.invitations.create = AsyncMock()

    uow.audit_events = MagicMock()
    uow.audit_events.create = AsyncMock()

    return uow


@pytest.mark.asyncio
async def test_successful_invite_by_owner(mock_uow):
    """Test successful invitation by tenant owner - AC-6.1"""
    # Arrange
    inviter_user_id = uuid4()
    tenant_id = uuid4()
    email = "newuser@company.com"
    role = "member"

    # Inviter is owner
    inviter_membership = Membership(
        id=uuid4(),
        user_id=inviter_user_id,
        tenant_id=tenant_id,
        role=MembershipRole.owner,
        status=MembershipStatus.active,
    )
    mock_uow.memberships.get_by_user_and_tenant.return_value = inviter_membership

    # No existing user with this email
    mock_uow.users.get_by_email.return_value = None

    # No pending invitation
    mock_uow.invitations.get_pending_by_tenant_and_email.return_value = None

    # Mock invitation creation
    invitation_id = uuid4()
    mock_invitation = Invitation(
        id=invitation_id,
        tenant_id=tenant_id,
        email=email,
        role=MembershipRole.member,
        token="secure_token_123",
        status=InvitationStatus.pending,
    )
    mock_uow.invitations.create.return_value = mock_invitation

    use_case = InviteUserUseCase(mock_uow)

    # Act
    result = await use_case.execute(inviter_user_id, tenant_id, email, role)

    # Assert
    assert result.is_ok()
    response = result.value
    # Note: invite_id will be newly generated UUID, not the mocked one
    assert response.invite_id is not None
    assert len(response.invite_id) == 36  # UUID string length
    assert response.status == "pending"
    assert response.expires_at is not None

    # Verify all repositories were called
    mock_uow.memberships.get_by_user_and_tenant.assert_called_once_with(
        inviter_user_id, tenant_id
    )
    mock_uow.users.get_by_email.assert_called_once_with(email)
    mock_uow.invitations.get_pending_by_tenant_and_email.assert_called_once_with(
        tenant_id, email
    )
    mock_uow.invitations.create.assert_called_once()
    mock_uow.audit_events.create.assert_called_once()
    mock_uow.commit.assert_called_once()


@pytest.mark.asyncio
async def test_successful_invite_by_admin(mock_uow):
    """Test successful invitation by tenant admin - AC-6.1"""
    # Arrange
    inviter_user_id = uuid4()
    tenant_id = uuid4()
    email = "newuser@company.com"
    role = "member"

    # Inviter is admin
    inviter_membership = Membership(
        id=uuid4(),
        user_id=inviter_user_id,
        tenant_id=tenant_id,
        role=MembershipRole.admin,
        status=MembershipStatus.active,
    )
    mock_uow.memberships.get_by_user_and_tenant.return_value = inviter_membership

    # No existing user with this email
    mock_uow.users.get_by_email.return_value = None

    # No pending invitation
    mock_uow.invitations.get_pending_by_tenant_and_email.return_value = None

    # Mock invitation creation
    invitation_id = uuid4()
    mock_invitation = Invitation(
        id=invitation_id,
        tenant_id=tenant_id,
        email=email,
        role=MembershipRole.member,
        token="secure_token_123",
        status=InvitationStatus.pending,
    )
    mock_uow.invitations.create.return_value = mock_invitation

    use_case = InviteUserUseCase(mock_uow)

    # Act
    result = await use_case.execute(inviter_user_id, tenant_id, email, role)

    # Assert
    assert result.is_ok()
    assert mock_uow.commit.assert_called_once


@pytest.mark.asyncio
async def test_insufficient_role_member(mock_uow):
    """Test that members cannot invite users - AC-6.2"""
    # Arrange
    inviter_user_id = uuid4()
    tenant_id = uuid4()
    email = "newuser@company.com"
    role = "member"

    # Inviter is just a member (not owner/admin)
    inviter_membership = Membership(
        id=uuid4(),
        user_id=inviter_user_id,
        tenant_id=tenant_id,
        role=MembershipRole.member,
        status=MembershipStatus.active,
    )
    mock_uow.memberships.get_by_user_and_tenant.return_value = inviter_membership

    use_case = InviteUserUseCase(mock_uow)

    # Act
    result = await use_case.execute(inviter_user_id, tenant_id, email, role)

    # Assert
    assert result.is_err()
    assert result.error.code == "INSUFFICIENT_ROLE"
    assert "owners and admins" in result.error.message.lower()

    # Verify invitation was not created
    mock_uow.invitations.create.assert_not_called()
    mock_uow.commit.assert_not_called()


@pytest.mark.asyncio
async def test_insufficient_role_viewer(mock_uow):
    """Test that viewers cannot invite users - AC-6.2"""
    # Arrange
    inviter_user_id = uuid4()
    tenant_id = uuid4()
    email = "newuser@company.com"
    role = "member"

    # Inviter is viewer
    inviter_membership = Membership(
        id=uuid4(),
        user_id=inviter_user_id,
        tenant_id=tenant_id,
        role=MembershipRole.viewer,
        status=MembershipStatus.active,
    )
    mock_uow.memberships.get_by_user_and_tenant.return_value = inviter_membership

    use_case = InviteUserUseCase(mock_uow)

    # Act
    result = await use_case.execute(inviter_user_id, tenant_id, email, role)

    # Assert
    assert result.is_err()
    assert result.error.code == "INSUFFICIENT_ROLE"


@pytest.mark.asyncio
async def test_duplicate_pending_invitation(mock_uow):
    """Test preventing duplicate pending invitations - AC-6.3"""
    # Arrange
    inviter_user_id = uuid4()
    tenant_id = uuid4()
    email = "newuser@company.com"
    role = "member"

    # Inviter is owner
    inviter_membership = Membership(
        id=uuid4(),
        user_id=inviter_user_id,
        tenant_id=tenant_id,
        role=MembershipRole.owner,
        status=MembershipStatus.active,
    )
    mock_uow.memberships.get_by_user_and_tenant.return_value = inviter_membership

    # No existing user
    mock_uow.users.get_by_email.return_value = None

    # Existing pending invitation
    existing_invitation = Invitation(
        id=uuid4(),
        tenant_id=tenant_id,
        email=email,
        role=MembershipRole.member,
        token="existing_token",
        status=InvitationStatus.pending,
    )
    mock_uow.invitations.get_pending_by_tenant_and_email.return_value = (
        existing_invitation
    )

    use_case = InviteUserUseCase(mock_uow)

    # Act
    result = await use_case.execute(inviter_user_id, tenant_id, email, role)

    # Assert
    assert result.is_err()
    assert result.error.code == "INVITE_ALREADY_EXISTS"
    assert "pending invitation" in result.error.message.lower()

    # Verify new invitation was not created
    mock_uow.invitations.create.assert_not_called()
    mock_uow.commit.assert_not_called()


@pytest.mark.asyncio
async def test_user_already_member(mock_uow):
    """Test preventing invitation of existing members - AC-6.4"""
    # Arrange
    inviter_user_id = uuid4()
    tenant_id = uuid4()
    existing_user_id = uuid4()
    email = "existing@company.com"
    role = "member"

    # Inviter is owner
    inviter_membership = Membership(
        id=uuid4(),
        user_id=inviter_user_id,
        tenant_id=tenant_id,
        role=MembershipRole.owner,
        status=MembershipStatus.active,
    )

    # User exists
    existing_user = User(id=existing_user_id, email=email, password_hash="hash")
    mock_uow.users.get_by_email.return_value = existing_user

    # User already has membership
    existing_membership = Membership(
        id=uuid4(),
        user_id=existing_user_id,
        tenant_id=tenant_id,
        role=MembershipRole.member,
        status=MembershipStatus.active,
    )

    # Mock get_by_user_and_tenant to return different values based on user_id
    async def mock_get_by_user_and_tenant(user_id, tenant_id_param):
        if user_id == inviter_user_id:
            return inviter_membership
        elif user_id == existing_user_id:
            return existing_membership
        return None

    mock_uow.memberships.get_by_user_and_tenant.side_effect = (
        mock_get_by_user_and_tenant
    )

    # No pending invitation
    mock_uow.invitations.get_pending_by_tenant_and_email.return_value = None

    use_case = InviteUserUseCase(mock_uow)

    # Act
    result = await use_case.execute(inviter_user_id, tenant_id, email, role)

    # Assert
    assert result.is_err()
    assert result.error.code == "ALREADY_MEMBER"
    assert "already a member" in result.error.message.lower()

    # Verify invitation was not created
    mock_uow.invitations.create.assert_not_called()
    mock_uow.commit.assert_not_called()


@pytest.mark.asyncio
async def test_invalid_role(mock_uow):
    """Test invalid role validation - AC-6.5"""
    # Arrange
    inviter_user_id = uuid4()
    tenant_id = uuid4()
    email = "newuser@company.com"
    invalid_role = "superadmin"  # Invalid role

    # Inviter is owner
    inviter_membership = Membership(
        id=uuid4(),
        user_id=inviter_user_id,
        tenant_id=tenant_id,
        role=MembershipRole.owner,
        status=MembershipStatus.active,
    )
    mock_uow.memberships.get_by_user_and_tenant.return_value = inviter_membership

    use_case = InviteUserUseCase(mock_uow)

    # Act
    result = await use_case.execute(inviter_user_id, tenant_id, email, invalid_role)

    # Assert
    assert result.is_err()
    assert result.error.code == "INVALID_ROLE"
    assert "invalid role" in result.error.message.lower()

    # Verify invitation was not created
    mock_uow.invitations.create.assert_not_called()
    mock_uow.commit.assert_not_called()


@pytest.mark.asyncio
async def test_inviter_not_a_member(mock_uow):
    """Test that non-members cannot invite users"""
    # Arrange
    inviter_user_id = uuid4()
    tenant_id = uuid4()
    email = "newuser@company.com"
    role = "member"

    # Inviter has no membership
    mock_uow.memberships.get_by_user_and_tenant.return_value = None

    use_case = InviteUserUseCase(mock_uow)

    # Act
    result = await use_case.execute(inviter_user_id, tenant_id, email, role)

    # Assert
    assert result.is_err()
    assert result.error.code == "NOT_A_MEMBER"

    # Verify invitation was not created
    mock_uow.invitations.create.assert_not_called()
    mock_uow.commit.assert_not_called()


@pytest.mark.asyncio
async def test_invite_with_owner_role(mock_uow):
    """Test inviting a user with owner role"""
    # Arrange
    inviter_user_id = uuid4()
    tenant_id = uuid4()
    email = "newowner@company.com"
    role = "owner"

    # Inviter is owner
    inviter_membership = Membership(
        id=uuid4(),
        user_id=inviter_user_id,
        tenant_id=tenant_id,
        role=MembershipRole.owner,
        status=MembershipStatus.active,
    )
    mock_uow.memberships.get_by_user_and_tenant.return_value = inviter_membership

    # No existing user
    mock_uow.users.get_by_email.return_value = None

    # No pending invitation
    mock_uow.invitations.get_pending_by_tenant_and_email.return_value = None

    # Mock invitation creation
    mock_invitation = Invitation(
        id=uuid4(),
        tenant_id=tenant_id,
        email=email,
        role=MembershipRole.owner,
        token="secure_token_123",
        status=InvitationStatus.pending,
    )
    mock_uow.invitations.create.return_value = mock_invitation

    use_case = InviteUserUseCase(mock_uow)

    # Act
    result = await use_case.execute(inviter_user_id, tenant_id, email, role)

    # Assert
    assert result.is_ok()
    response = result.value
    assert response.status == "pending"

    # Verify invitation was created
    mock_uow.invitations.create.assert_called_once()
    created_invitation = mock_uow.invitations.create.call_args[0][0]
    assert created_invitation.role == MembershipRole.owner


@pytest.mark.asyncio
async def test_invite_user_not_yet_registered(mock_uow):
    """Test inviting a user who doesn't have an account yet"""
    # Arrange
    inviter_user_id = uuid4()
    tenant_id = uuid4()
    email = "newuser@company.com"
    role = "member"

    # Inviter is owner
    inviter_membership = Membership(
        id=uuid4(),
        user_id=inviter_user_id,
        tenant_id=tenant_id,
        role=MembershipRole.owner,
        status=MembershipStatus.active,
    )
    mock_uow.memberships.get_by_user_and_tenant.return_value = inviter_membership

    # User doesn't exist yet
    mock_uow.users.get_by_email.return_value = None

    # No pending invitation
    mock_uow.invitations.get_pending_by_tenant_and_email.return_value = None

    # Mock invitation creation
    mock_invitation = Invitation(
        id=uuid4(),
        tenant_id=tenant_id,
        email=email,
        role=MembershipRole.member,
        token="secure_token_123",
        status=InvitationStatus.pending,
    )
    mock_uow.invitations.create.return_value = mock_invitation

    use_case = InviteUserUseCase(mock_uow)

    # Act
    result = await use_case.execute(inviter_user_id, tenant_id, email, role)

    # Assert
    assert result.is_ok()
    # Verify invitation was created even though user doesn't exist
    mock_uow.invitations.create.assert_called_once()
