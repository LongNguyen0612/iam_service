import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

# Add monorepo root to Python path for libs access
monorepo_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(monorepo_root))

from libs.result import Error
from src.app.use_cases.tenants.remove_member_use_case import RemoveMemberUseCase
from src.domain.entities import (
    Membership,
    MembershipRole,
    MembershipStatus,
    Session,
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
    uow.memberships.get_by_tenant_id = AsyncMock()
    uow.memberships.update = AsyncMock()

    uow.sessions = MagicMock()
    uow.sessions.get_by_user_and_tenant = AsyncMock()
    uow.sessions.update = AsyncMock()

    uow.audit_events = MagicMock()
    uow.audit_events.create = AsyncMock()

    return uow


@pytest.mark.asyncio
async def test_successful_member_removal_by_owner(mock_uow):
    """Test successful member removal by owner - AC-16.1"""
    # Arrange
    requester_user_id = uuid4()
    target_user_id = uuid4()
    tenant_id = uuid4()

    # Requester is owner
    requester_membership = Membership(
        id=uuid4(),
        user_id=requester_user_id,
        tenant_id=tenant_id,
        role=MembershipRole.owner,
        status=MembershipStatus.active,
    )

    # Target is member
    target_membership = Membership(
        id=uuid4(),
        user_id=target_user_id,
        tenant_id=tenant_id,
        role=MembershipRole.member,
        status=MembershipStatus.active,
    )

    mock_uow.memberships.get_by_user_and_tenant.side_effect = [
        requester_membership,  # First call for requester
        target_membership,  # Second call for target
    ]

    # Mock sessions for target user
    session1 = Session(
        id=uuid4(),
        user_id=target_user_id,
        tenant_id=tenant_id,
        refresh_token_hash="hash1",
        revoked=False,
    )
    mock_uow.sessions.get_by_user_and_tenant.return_value = [session1]

    # Act
    use_case = RemoveMemberUseCase(mock_uow)
    result = await use_case.execute(requester_user_id, tenant_id, target_user_id)

    # Assert
    assert result.is_ok()
    assert result.value.status == "removed"

    # Verify membership was updated to revoked (AC-16.1)
    assert target_membership.status == MembershipStatus.revoked
    mock_uow.memberships.update.assert_called_once()

    # Verify sessions were revoked (AC-16.1)
    assert session1.revoked is True
    mock_uow.sessions.update.assert_called_once()

    # Verify audit event was created (AC-16.1)
    mock_uow.audit_events.create.assert_called_once()

    # Verify commit
    mock_uow.commit.assert_called_once()


@pytest.mark.asyncio
async def test_successful_member_removal_by_admin(mock_uow):
    """Test successful member removal by admin"""
    # Arrange
    requester_user_id = uuid4()
    target_user_id = uuid4()
    tenant_id = uuid4()

    # Requester is admin
    requester_membership = Membership(
        id=uuid4(),
        user_id=requester_user_id,
        tenant_id=tenant_id,
        role=MembershipRole.admin,
        status=MembershipStatus.active,
    )

    # Target is viewer
    target_membership = Membership(
        id=uuid4(),
        user_id=target_user_id,
        tenant_id=tenant_id,
        role=MembershipRole.viewer,
        status=MembershipStatus.active,
    )

    mock_uow.memberships.get_by_user_and_tenant.side_effect = [
        requester_membership,
        target_membership,
    ]
    mock_uow.sessions.get_by_user_and_tenant.return_value = []

    # Act
    use_case = RemoveMemberUseCase(mock_uow)
    result = await use_case.execute(requester_user_id, tenant_id, target_user_id)

    # Assert
    assert result.is_ok()
    assert result.value.status == "removed"
    assert target_membership.status == MembershipStatus.revoked


@pytest.mark.asyncio
async def test_owner_removes_self_with_multiple_owners(mock_uow):
    """Test owner can remove themselves when there are multiple owners - AC-16.3"""
    # Arrange
    owner1_user_id = uuid4()
    owner2_user_id = uuid4()
    tenant_id = uuid4()

    # Owner1 is removing themselves
    owner1_membership = Membership(
        id=uuid4(),
        user_id=owner1_user_id,
        tenant_id=tenant_id,
        role=MembershipRole.owner,
        status=MembershipStatus.active,
    )

    # Owner2 exists
    owner2_membership = Membership(
        id=uuid4(),
        user_id=owner2_user_id,
        tenant_id=tenant_id,
        role=MembershipRole.owner,
        status=MembershipStatus.active,
    )

    mock_uow.memberships.get_by_user_and_tenant.side_effect = [
        owner1_membership,  # Requester lookup
        owner1_membership,  # Target lookup (same person)
    ]

    # Return 2 owners when counting
    mock_uow.memberships.get_by_tenant_id.return_value = [
        owner1_membership,
        owner2_membership,
    ]
    mock_uow.sessions.get_by_user_and_tenant.return_value = []

    # Act
    use_case = RemoveMemberUseCase(mock_uow)
    result = await use_case.execute(owner1_user_id, tenant_id, owner1_user_id)

    # Assert
    assert result.is_ok()
    assert result.value.status == "removed"
    assert owner1_membership.status == MembershipStatus.revoked


@pytest.mark.asyncio
async def test_cannot_remove_last_owner(mock_uow):
    """Test owner cannot remove themselves if they're the last owner - AC-16.2"""
    # Arrange
    owner_user_id = uuid4()
    tenant_id = uuid4()

    # Only one owner
    owner_membership = Membership(
        id=uuid4(),
        user_id=owner_user_id,
        tenant_id=tenant_id,
        role=MembershipRole.owner,
        status=MembershipStatus.active,
    )

    mock_uow.memberships.get_by_user_and_tenant.side_effect = [
        owner_membership,  # Requester lookup
        owner_membership,  # Target lookup (same person)
    ]

    # Return only 1 owner when counting
    mock_uow.memberships.get_by_tenant_id.return_value = [owner_membership]

    # Act
    use_case = RemoveMemberUseCase(mock_uow)
    result = await use_case.execute(owner_user_id, tenant_id, owner_user_id)

    # Assert
    assert result.is_err()
    assert result.error.code == "CANNOT_REMOVE_LAST_OWNER"

    # Verify membership was NOT updated
    mock_uow.memberships.update.assert_not_called()


@pytest.mark.asyncio
async def test_admin_cannot_remove_owner(mock_uow):
    """Test admin cannot remove an owner - AC-16.4"""
    # Arrange
    admin_user_id = uuid4()
    owner_user_id = uuid4()
    tenant_id = uuid4()

    # Requester is admin
    admin_membership = Membership(
        id=uuid4(),
        user_id=admin_user_id,
        tenant_id=tenant_id,
        role=MembershipRole.admin,
        status=MembershipStatus.active,
    )

    # Target is owner
    owner_membership = Membership(
        id=uuid4(),
        user_id=owner_user_id,
        tenant_id=tenant_id,
        role=MembershipRole.owner,
        status=MembershipStatus.active,
    )

    mock_uow.memberships.get_by_user_and_tenant.side_effect = [
        admin_membership,
        owner_membership,
    ]

    # Act
    use_case = RemoveMemberUseCase(mock_uow)
    result = await use_case.execute(admin_user_id, tenant_id, owner_user_id)

    # Assert
    assert result.is_err()
    assert result.error.code == "INSUFFICIENT_ROLE"

    # Verify membership was NOT updated
    mock_uow.memberships.update.assert_not_called()


@pytest.mark.asyncio
async def test_member_cannot_remove_anyone(mock_uow):
    """Test member cannot remove other members"""
    # Arrange
    member_user_id = uuid4()
    target_user_id = uuid4()
    tenant_id = uuid4()

    # Requester is member
    member_membership = Membership(
        id=uuid4(),
        user_id=member_user_id,
        tenant_id=tenant_id,
        role=MembershipRole.member,
        status=MembershipStatus.active,
    )

    mock_uow.memberships.get_by_user_and_tenant.return_value = member_membership

    # Act
    use_case = RemoveMemberUseCase(mock_uow)
    result = await use_case.execute(member_user_id, tenant_id, target_user_id)

    # Assert
    assert result.is_err()
    assert result.error.code == "INSUFFICIENT_ROLE"


@pytest.mark.asyncio
async def test_membership_not_found(mock_uow):
    """Test removal fails when target user is not a member"""
    # Arrange
    owner_user_id = uuid4()
    target_user_id = uuid4()
    tenant_id = uuid4()

    # Requester is owner
    owner_membership = Membership(
        id=uuid4(),
        user_id=owner_user_id,
        tenant_id=tenant_id,
        role=MembershipRole.owner,
        status=MembershipStatus.active,
    )

    mock_uow.memberships.get_by_user_and_tenant.side_effect = [
        owner_membership,  # Requester lookup
        None,  # Target not found
    ]

    # Act
    use_case = RemoveMemberUseCase(mock_uow)
    result = await use_case.execute(owner_user_id, tenant_id, target_user_id)

    # Assert
    assert result.is_err()
    assert result.error.code == "MEMBERSHIP_NOT_FOUND"


@pytest.mark.asyncio
async def test_requester_not_a_member(mock_uow):
    """Test removal fails when requester is not a member"""
    # Arrange
    requester_user_id = uuid4()
    target_user_id = uuid4()
    tenant_id = uuid4()

    # Requester is not a member
    mock_uow.memberships.get_by_user_and_tenant.return_value = None

    # Act
    use_case = RemoveMemberUseCase(mock_uow)
    result = await use_case.execute(requester_user_id, tenant_id, target_user_id)

    # Assert
    assert result.is_err()
    assert result.error.code == "NOT_A_MEMBER"
