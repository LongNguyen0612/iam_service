"""
Unit tests for DeleteTenantUseCase (IAM-018)

Tests business logic in isolation with mocked repositories.
"""

import pytest
from datetime import datetime, UTC, timedelta
from uuid import uuid4
from unittest.mock import AsyncMock, MagicMock
from src.app.use_cases.tenants.delete_tenant_use_case import DeleteTenantUseCase
from src.domain.entities import Tenant, Membership, Session, MembershipRole, MembershipStatus


@pytest.mark.asyncio
async def test_successful_tenant_deletion(mock_uow, mock_audit_service):
    """Test successful tenant deletion"""
    # Arrange
    user_id = uuid4()
    tenant_id = uuid4()
    tenant = Tenant(id=tenant_id, name="Acme Corp", status="active", deleted_at=None)
    membership = Membership(
        user_id=user_id,
        tenant_id=tenant_id,
        role=MembershipRole.owner,
        status=MembershipStatus.active,
    )
    session1 = Session(
        user_id=user_id, tenant_id=tenant_id, revoked=False, refresh_token_hash="hash1"
    )
    session2 = Session(
        user_id=user_id, tenant_id=tenant_id, revoked=False, refresh_token_hash="hash2"
    )

    mock_uow.tenants.get_by_id = AsyncMock(return_value=tenant)
    mock_uow.memberships.get_by_user_and_tenant = AsyncMock(return_value=membership)
    mock_uow.sessions.get_active_by_tenant_id = AsyncMock(return_value=[session1, session2])
    mock_uow.tenants.update = AsyncMock(return_value=tenant)
    mock_uow.sessions.update = AsyncMock()
    
    use_case = DeleteTenantUseCase(mock_uow, mock_audit_service)

    # Act
    result = await use_case.execute(
        user_id=user_id,
        tenant_id=tenant_id,
        confirmation="DELETE_TENANT_Acme_Corp",
    )

    # Assert
    assert result.is_ok()
    response = result.value
    assert response.status == "deletion_initiated"
    assert response.sessions_revoked == 2
    assert "purge_scheduled_at" in response.model_dump()
    assert "rollback_deadline" in response.model_dump()

    # Verify tenant was updated
    assert tenant.status.value == "suspended"
    assert tenant.deleted_at is not None
    assert mock_uow.tenants.update.await_count == 1

    # Verify sessions were revoked
    assert session1.revoked is True
    assert session1.revoked_at is not None
    assert session2.revoked is True
    assert session2.revoked_at is not None
    assert mock_uow.sessions.update.await_count == 2

    # Verify audit event was created
    mock_audit_service.log_event.assert_called_once()


@pytest.mark.asyncio
async def test_delete_tenant_not_found(mock_uow, mock_audit_service):
    """Test deletion when tenant doesn't exist"""
    user_id = uuid4()
    tenant_id = uuid4()

    mock_uow.tenants.get_by_id = AsyncMock(return_value=None)

    use_case = DeleteTenantUseCase(mock_uow, mock_audit_service)
    result = await use_case.execute(
        user_id=user_id,
        tenant_id=tenant_id,
        confirmation="DELETE_TENANT_Test",
    )

    assert result.is_err()
    assert result.error.code == "TENANT_NOT_FOUND"


@pytest.mark.asyncio
async def test_delete_tenant_insufficient_role(mock_uow, mock_audit_service):
    """Test deletion by non-owner (admin/member)"""
    user_id = uuid4()
    tenant_id = uuid4()
    tenant = Tenant(id=tenant_id, name="Test Corp", status="active")
    membership = Membership(
        user_id=user_id,
        tenant_id=tenant_id,
        role=MembershipRole.admin,  # Not owner!
        status=MembershipStatus.active,
    )

    mock_uow.tenants.get_by_id = AsyncMock(return_value=tenant)
    mock_uow.memberships.get_by_user_and_tenant = AsyncMock(return_value=membership)

    use_case = DeleteTenantUseCase(mock_uow, mock_audit_service)
    result = await use_case.execute(
        user_id=user_id,
        tenant_id=tenant_id,
        confirmation="DELETE_TENANT_Test_Corp",
    )

    assert result.is_err()
    assert result.error.code == "INSUFFICIENT_ROLE"


@pytest.mark.asyncio
async def test_delete_tenant_invalid_confirmation(mock_uow, mock_audit_service):
    """Test deletion with wrong confirmation string"""
    user_id = uuid4()
    tenant_id = uuid4()
    tenant = Tenant(id=tenant_id, name="Acme Corp", status="active")
    membership = Membership(
        user_id=user_id,
        tenant_id=tenant_id,
        role=MembershipRole.owner,
        status=MembershipStatus.active,
    )

    mock_uow.tenants.get_by_id = AsyncMock(return_value=tenant)
    mock_uow.memberships.get_by_user_and_tenant = AsyncMock(return_value=membership)

    use_case = DeleteTenantUseCase(mock_uow, mock_audit_service)
    result = await use_case.execute(
        user_id=user_id,
        tenant_id=tenant_id,
        confirmation="WRONG_CONFIRMATION",  # Wrong!
    )

    assert result.is_err()
    assert result.error.code == "INVALID_CONFIRMATION"
    assert "DELETE_TENANT_Acme_Corp" in result.error.message


@pytest.mark.asyncio
async def test_delete_tenant_already_deleted(mock_uow, mock_audit_service):
    """Test deletion of already deleted tenant"""
    user_id = uuid4()
    tenant_id = uuid4()
    tenant = Tenant(
        id=tenant_id,
        name="Test Corp",
        status="suspended",
        deleted_at=datetime.now(UTC) - timedelta(days=1),  # Already deleted
    )
    membership = Membership(
        user_id=user_id,
        tenant_id=tenant_id,
        role=MembershipRole.owner,
        status=MembershipStatus.active,
    )

    mock_uow.tenants.get_by_id = AsyncMock(return_value=tenant)
    mock_uow.memberships.get_by_user_and_tenant = AsyncMock(return_value=membership)

    use_case = DeleteTenantUseCase(mock_uow, mock_audit_service)
    result = await use_case.execute(
        user_id=user_id,
        tenant_id=tenant_id,
        confirmation="DELETE_TENANT_Test_Corp",
    )

    assert result.is_err()
    assert result.error.code == "ALREADY_DELETED"


@pytest.mark.asyncio
async def test_delete_tenant_with_no_sessions(mock_uow, mock_audit_service):
    """Test deletion when no active sessions exist"""
    user_id = uuid4()
    tenant_id = uuid4()
    tenant = Tenant(id=tenant_id, name="Empty Corp", status="active")
    membership = Membership(
        user_id=user_id,
        tenant_id=tenant_id,
        role=MembershipRole.owner,
        status=MembershipStatus.active,
    )

    mock_uow.tenants.get_by_id = AsyncMock(return_value=tenant)
    mock_uow.memberships.get_by_user_and_tenant = AsyncMock(return_value=membership)
    mock_uow.sessions.get_active_by_tenant_id = AsyncMock(return_value=[])
    mock_uow.tenants.update = AsyncMock()
    
    use_case = DeleteTenantUseCase(mock_uow, mock_audit_service)
    result = await use_case.execute(
        user_id=user_id,
        tenant_id=tenant_id,
        confirmation="DELETE_TENANT_Empty_Corp",
    )

    assert result.is_ok()
    assert result.value.sessions_revoked == 0


@pytest.mark.asyncio
async def test_delete_tenant_no_membership(mock_uow, mock_audit_service):
    """Test deletion when user is not a member"""
    user_id = uuid4()
    tenant_id = uuid4()
    tenant = Tenant(id=tenant_id, name="Test Corp", status="active")

    mock_uow.tenants.get_by_id = AsyncMock(return_value=tenant)
    mock_uow.memberships.get_by_user_and_tenant = AsyncMock(
        return_value=None
    )  # No membership

    use_case = DeleteTenantUseCase(mock_uow, mock_audit_service)
    result = await use_case.execute(
        user_id=user_id,
        tenant_id=tenant_id,
        confirmation="DELETE_TENANT_Test_Corp",
    )

    assert result.is_err()
    assert result.error.code == "INSUFFICIENT_ROLE"


@pytest.mark.asyncio
async def test_delete_tenant_confirmation_with_spaces(mock_uow, mock_audit_service):
    """Test confirmation string handles tenant names with spaces correctly"""
    user_id = uuid4()
    tenant_id = uuid4()
    tenant = Tenant(id=tenant_id, name="My Company Name", status="active")
    membership = Membership(
        user_id=user_id,
        tenant_id=tenant_id,
        role=MembershipRole.owner,
        status=MembershipStatus.active,
    )

    mock_uow.tenants.get_by_id = AsyncMock(return_value=tenant)
    mock_uow.memberships.get_by_user_and_tenant = AsyncMock(return_value=membership)
    mock_uow.sessions.get_active_by_tenant_id = AsyncMock(return_value=[])
    mock_uow.tenants.update = AsyncMock()
    
    use_case = DeleteTenantUseCase(mock_uow, mock_audit_service)
    result = await use_case.execute(
        user_id=user_id,
        tenant_id=tenant_id,
        confirmation="DELETE_TENANT_My_Company_Name",  # Spaces replaced with underscores
    )

    assert result.is_ok()
    assert result.value.status == "deletion_initiated"
