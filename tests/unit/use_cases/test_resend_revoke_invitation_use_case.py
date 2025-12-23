import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

# Add monorepo root to Python path for libs access
monorepo_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(monorepo_root))

from libs.result import Error
from src.app.use_cases.tenants.resend_invitation_use_case import ResendInvitationUseCase
from src.app.use_cases.tenants.revoke_invitation_use_case import RevokeInvitationUseCase
from src.domain.entities import (
    Invitation,
    InvitationStatus,
    Membership,
    MembershipRole,
    MembershipStatus,
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
    uow.memberships = MagicMock()
    uow.memberships.get_by_user_and_tenant = AsyncMock()

    uow.invitations = MagicMock()
    uow.invitations.get_by_id = AsyncMock()
    uow.invitations.update = AsyncMock()

    uow.audit_events = MagicMock()
    uow.audit_events.create = AsyncMock()

    return uow


# ============================================================================
# Resend Invitation Tests
# ============================================================================


@pytest.mark.asyncio
async def test_successful_resend_invitation(mock_uow):
    """Test successful resend of pending invitation - AC-15.1"""
    # Arrange
    user_id = uuid4()
    tenant_id = uuid4()
    invitation_id = uuid4()

    # User is admin
    admin_membership = Membership(
        id=uuid4(),
        user_id=user_id,
        tenant_id=tenant_id,
        role=MembershipRole.admin,
        status=MembershipStatus.active,
    )
    mock_uow.memberships.get_by_user_and_tenant.return_value = admin_membership

    # Pending invitation exists
    original_expiry = datetime.now(UTC) - timedelta(hours=1)  # Expired
    pending_invitation = Invitation(
        id=invitation_id,
        tenant_id=tenant_id,
        email="user@company.com",
        role=MembershipRole.member,
        token="token123",
        status=InvitationStatus.pending,
        expires_at=original_expiry,
    )
    mock_uow.invitations.get_by_id.return_value = pending_invitation

    # Act
    use_case = ResendInvitationUseCase(mock_uow)
    result = await use_case.execute(user_id, tenant_id, invitation_id)

    # Assert
    assert result.is_ok()
    assert result.value.status == "resent"

    # Verify expiry was extended by 7 days
    updated_invitation = pending_invitation
    assert updated_invitation.expires_at > datetime.now(UTC) + timedelta(days=6)

    # Verify update was called
    mock_uow.invitations.update.assert_called_once()

    # Verify audit event was created
    mock_uow.audit_events.create.assert_called_once()

    # Verify commit
    mock_uow.commit.assert_called_once()


@pytest.mark.asyncio
async def test_resend_invitation_insufficient_role(mock_uow):
    """Test resend fails when user is not admin/owner"""
    # Arrange
    user_id = uuid4()
    tenant_id = uuid4()
    invitation_id = uuid4()

    # User is only a member
    member_membership = Membership(
        id=uuid4(),
        user_id=user_id,
        tenant_id=tenant_id,
        role=MembershipRole.member,
        status=MembershipStatus.active,
    )
    mock_uow.memberships.get_by_user_and_tenant.return_value = member_membership

    # Act
    use_case = ResendInvitationUseCase(mock_uow)
    result = await use_case.execute(user_id, tenant_id, invitation_id)

    # Assert
    assert result.is_err()
    assert result.error.code == "INSUFFICIENT_ROLE"


@pytest.mark.asyncio
async def test_resend_invitation_already_accepted(mock_uow):
    """Test resend fails when invitation already accepted - AC-15.3"""
    # Arrange
    user_id = uuid4()
    tenant_id = uuid4()
    invitation_id = uuid4()

    # User is admin
    admin_membership = Membership(
        id=uuid4(),
        user_id=user_id,
        tenant_id=tenant_id,
        role=MembershipRole.admin,
        status=MembershipStatus.active,
    )
    mock_uow.memberships.get_by_user_and_tenant.return_value = admin_membership

    # Invitation already accepted
    accepted_invitation = Invitation(
        id=invitation_id,
        tenant_id=tenant_id,
        email="user@company.com",
        role=MembershipRole.member,
        token="token123",
        status=InvitationStatus.accepted,
        expires_at=datetime.now(UTC) + timedelta(days=7),
    )
    mock_uow.invitations.get_by_id.return_value = accepted_invitation

    # Act
    use_case = ResendInvitationUseCase(mock_uow)
    result = await use_case.execute(user_id, tenant_id, invitation_id)

    # Assert
    assert result.is_err()
    assert result.error.code == "INVITATION_ALREADY_ACCEPTED"

    # Verify update was NOT called
    mock_uow.invitations.update.assert_not_called()


@pytest.mark.asyncio
async def test_resend_invitation_not_found(mock_uow):
    """Test resend fails when invitation doesn't exist"""
    # Arrange
    user_id = uuid4()
    tenant_id = uuid4()
    invitation_id = uuid4()

    # User is admin
    admin_membership = Membership(
        id=uuid4(),
        user_id=user_id,
        tenant_id=tenant_id,
        role=MembershipRole.admin,
        status=MembershipStatus.active,
    )
    mock_uow.memberships.get_by_user_and_tenant.return_value = admin_membership

    # Invitation doesn't exist
    mock_uow.invitations.get_by_id.return_value = None

    # Act
    use_case = ResendInvitationUseCase(mock_uow)
    result = await use_case.execute(user_id, tenant_id, invitation_id)

    # Assert
    assert result.is_err()
    assert result.error.code == "INVITATION_NOT_FOUND"


@pytest.mark.asyncio
async def test_resend_invitation_wrong_tenant(mock_uow):
    """Test resend fails when invitation belongs to different tenant"""
    # Arrange
    user_id = uuid4()
    tenant_id = uuid4()
    other_tenant_id = uuid4()
    invitation_id = uuid4()

    # User is admin
    admin_membership = Membership(
        id=uuid4(),
        user_id=user_id,
        tenant_id=tenant_id,
        role=MembershipRole.admin,
        status=MembershipStatus.active,
    )
    mock_uow.memberships.get_by_user_and_tenant.return_value = admin_membership

    # Invitation belongs to different tenant
    invitation = Invitation(
        id=invitation_id,
        tenant_id=other_tenant_id,  # Different tenant!
        email="user@company.com",
        role=MembershipRole.member,
        token="token123",
        status=InvitationStatus.pending,
        expires_at=datetime.now(UTC) + timedelta(days=7),
    )
    mock_uow.invitations.get_by_id.return_value = invitation

    # Act
    use_case = ResendInvitationUseCase(mock_uow)
    result = await use_case.execute(user_id, tenant_id, invitation_id)

    # Assert
    assert result.is_err()
    assert result.error.code == "INVITATION_NOT_FOUND"


# ============================================================================
# Revoke Invitation Tests
# ============================================================================


@pytest.mark.asyncio
async def test_successful_revoke_invitation(mock_uow):
    """Test successful revoke of pending invitation - AC-15.2"""
    # Arrange
    user_id = uuid4()
    tenant_id = uuid4()
    invitation_id = uuid4()

    # User is owner
    owner_membership = Membership(
        id=uuid4(),
        user_id=user_id,
        tenant_id=tenant_id,
        role=MembershipRole.owner,
        status=MembershipStatus.active,
    )
    mock_uow.memberships.get_by_user_and_tenant.return_value = owner_membership

    # Pending invitation exists
    pending_invitation = Invitation(
        id=invitation_id,
        tenant_id=tenant_id,
        email="user@company.com",
        role=MembershipRole.member,
        token="token123",
        status=InvitationStatus.pending,
        expires_at=datetime.now(UTC) + timedelta(days=7),
    )
    mock_uow.invitations.get_by_id.return_value = pending_invitation

    # Act
    use_case = RevokeInvitationUseCase(mock_uow)
    result = await use_case.execute(user_id, tenant_id, invitation_id)

    # Assert
    assert result.is_ok()
    assert result.value.status == "revoked"

    # Verify status was changed to expired
    assert pending_invitation.status == InvitationStatus.expired

    # Verify update was called
    mock_uow.invitations.update.assert_called_once()

    # Verify audit event was created (AC-15.2)
    mock_uow.audit_events.create.assert_called_once()

    # Verify commit
    mock_uow.commit.assert_called_once()


@pytest.mark.asyncio
async def test_revoke_invitation_insufficient_role(mock_uow):
    """Test revoke fails when user is not admin/owner"""
    # Arrange
    user_id = uuid4()
    tenant_id = uuid4()
    invitation_id = uuid4()

    # User is only a viewer
    viewer_membership = Membership(
        id=uuid4(),
        user_id=user_id,
        tenant_id=tenant_id,
        role=MembershipRole.viewer,
        status=MembershipStatus.active,
    )
    mock_uow.memberships.get_by_user_and_tenant.return_value = viewer_membership

    # Act
    use_case = RevokeInvitationUseCase(mock_uow)
    result = await use_case.execute(user_id, tenant_id, invitation_id)

    # Assert
    assert result.is_err()
    assert result.error.code == "INSUFFICIENT_ROLE"


@pytest.mark.asyncio
async def test_revoke_invitation_already_accepted(mock_uow):
    """Test revoke fails when invitation already accepted - AC-15.3"""
    # Arrange
    user_id = uuid4()
    tenant_id = uuid4()
    invitation_id = uuid4()

    # User is owner
    owner_membership = Membership(
        id=uuid4(),
        user_id=user_id,
        tenant_id=tenant_id,
        role=MembershipRole.owner,
        status=MembershipStatus.active,
    )
    mock_uow.memberships.get_by_user_and_tenant.return_value = owner_membership

    # Invitation already accepted
    accepted_invitation = Invitation(
        id=invitation_id,
        tenant_id=tenant_id,
        email="user@company.com",
        role=MembershipRole.member,
        token="token123",
        status=InvitationStatus.accepted,
        expires_at=datetime.now(UTC) + timedelta(days=7),
    )
    mock_uow.invitations.get_by_id.return_value = accepted_invitation

    # Act
    use_case = RevokeInvitationUseCase(mock_uow)
    result = await use_case.execute(user_id, tenant_id, invitation_id)

    # Assert
    assert result.is_err()
    assert result.error.code == "INVITATION_ALREADY_ACCEPTED"

    # Verify status was NOT changed
    assert accepted_invitation.status == InvitationStatus.accepted

    # Verify update was NOT called
    mock_uow.invitations.update.assert_not_called()


@pytest.mark.asyncio
async def test_revoke_invitation_not_found(mock_uow):
    """Test revoke fails when invitation doesn't exist"""
    # Arrange
    user_id = uuid4()
    tenant_id = uuid4()
    invitation_id = uuid4()

    # User is admin
    admin_membership = Membership(
        id=uuid4(),
        user_id=user_id,
        tenant_id=tenant_id,
        role=MembershipRole.admin,
        status=MembershipStatus.active,
    )
    mock_uow.memberships.get_by_user_and_tenant.return_value = admin_membership

    # Invitation doesn't exist
    mock_uow.invitations.get_by_id.return_value = None

    # Act
    use_case = RevokeInvitationUseCase(mock_uow)
    result = await use_case.execute(user_id, tenant_id, invitation_id)

    # Assert
    assert result.is_err()
    assert result.error.code == "INVITATION_NOT_FOUND"
