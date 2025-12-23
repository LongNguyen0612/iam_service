"""
Unit tests for Suspend/Restore Tenant Use Cases (IAM-017)
Tests business logic in isolation with mocked dependencies.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4
from datetime import datetime, UTC

from src.app.use_cases.admin import (
    SuspendTenantUseCase,
    RestoreTenantUseCase,
)
from src.domain.entities import Tenant, Session
from src.domain.entities.enums import TenantStatus


@pytest.mark.asyncio
async def test_suspend_tenant_success(mock_uow, mock_audit_service):
    """Test successful tenant suspension"""
    # Arrange
    tenant_id = uuid4()
    tenant = Tenant(id=tenant_id, name="Test Corp", status=TenantStatus.active)

    session1 = Session(
        id=uuid4(),
        user_id=uuid4(),
        tenant_id=tenant_id,
        refresh_token_hash="hash1",
        revoked=False,
        expires_at=datetime.now(UTC),
    )
    session2 = Session(
        id=uuid4(),
        user_id=uuid4(),
        tenant_id=tenant_id,
        refresh_token_hash="hash2",
        revoked=False,
        expires_at=datetime.now(UTC),
    )

    mock_uow.tenants.get_by_id = AsyncMock(return_value=tenant)
    mock_uow.tenants.update = AsyncMock(return_value=tenant)
    mock_uow.sessions.get_active_by_tenant_id = AsyncMock(return_value=[session1, session2])
    mock_uow.sessions.update = AsyncMock()
    
    # Act
    use_case = SuspendTenantUseCase(mock_uow, mock_audit_service)
    result = await use_case.execute(tenant_id)

    # Assert
    assert result.is_ok()
    response = result.value
    assert response.status == "suspended"
    assert response.sessions_revoked == 2

    # Verify tenant status updated
    assert tenant.status == TenantStatus.suspended
    mock_uow.tenants.update.assert_called_once_with(tenant)

    # Verify sessions revoked
    assert mock_uow.sessions.update.call_count == 2
    assert session1.revoked is True
    assert session2.revoked is True
    assert session1.revoked_at is not None
    assert session2.revoked_at is not None

    # Verify audit event created
    mock_audit_service.log_event.assert_called_once()

    # Verify transaction committed
    mock_uow.commit.assert_called_once()


@pytest.mark.asyncio
async def test_suspend_tenant_not_found(mock_uow, mock_audit_service):
    """Test suspending non-existent tenant"""
    # Arrange
    tenant_id = uuid4()
    mock_uow.tenants.get_by_id = AsyncMock(return_value=None)

    # Act
    use_case = SuspendTenantUseCase(mock_uow, mock_audit_service)
    result = await use_case.execute(tenant_id)

    # Assert
    assert result.is_err()
    assert result.error.code == "TENANT_NOT_FOUND"
    mock_uow.commit.assert_not_called()


@pytest.mark.asyncio
async def test_suspend_tenant_no_active_sessions(mock_uow, mock_audit_service):
    """Test suspending tenant with no active sessions"""
    # Arrange
    tenant_id = uuid4()
    tenant = Tenant(id=tenant_id, name="Test Corp", status=TenantStatus.active)

    mock_uow.tenants.get_by_id = AsyncMock(return_value=tenant)
    mock_uow.tenants.update = AsyncMock(return_value=tenant)
    mock_uow.sessions.get_active_by_tenant_id = AsyncMock(return_value=[])
    
    # Act
    use_case = SuspendTenantUseCase(mock_uow, mock_audit_service)
    result = await use_case.execute(tenant_id)

    # Assert
    assert result.is_ok()
    response = result.value
    assert response.status == "suspended"
    assert response.sessions_revoked == 0

    # Verify tenant status still updated
    assert tenant.status == TenantStatus.suspended
    mock_uow.commit.assert_called_once()


@pytest.mark.asyncio
async def test_suspend_tenant_already_suspended(mock_uow, mock_audit_service):
    """Test suspending already-suspended tenant (idempotent)"""
    # Arrange
    tenant_id = uuid4()
    tenant = Tenant(id=tenant_id, name="Test Corp", status=TenantStatus.suspended)

    mock_uow.tenants.get_by_id = AsyncMock(return_value=tenant)
    mock_uow.tenants.update = AsyncMock(return_value=tenant)
    mock_uow.sessions.get_active_by_tenant_id = AsyncMock(return_value=[])
    
    # Act
    use_case = SuspendTenantUseCase(mock_uow, mock_audit_service)
    result = await use_case.execute(tenant_id)

    # Assert
    assert result.is_ok()
    response = result.value
    assert response.status == "suspended"
    assert response.sessions_revoked == 0


@pytest.mark.asyncio
async def test_restore_tenant_success(mock_uow, mock_audit_service):
    """Test successful tenant restoration"""
    # Arrange
    tenant_id = uuid4()
    tenant = Tenant(id=tenant_id, name="Test Corp", status=TenantStatus.suspended)

    mock_uow.tenants.get_by_id = AsyncMock(return_value=tenant)
    mock_uow.tenants.update = AsyncMock(return_value=tenant)
    
    # Act
    use_case = RestoreTenantUseCase(mock_uow, mock_audit_service)
    result = await use_case.execute(tenant_id)

    # Assert
    assert result.is_ok()
    response = result.value
    assert response.status == "active"

    # Verify tenant status updated
    assert tenant.status == TenantStatus.active
    mock_uow.tenants.update.assert_called_once_with(tenant)

    # Verify audit event created
    mock_audit_service.log_event.assert_called_once()

    # Verify transaction committed
    mock_uow.commit.assert_called_once()


@pytest.mark.asyncio
async def test_restore_tenant_not_found(mock_uow, mock_audit_service):
    """Test restoring non-existent tenant"""
    # Arrange
    tenant_id = uuid4()
    mock_uow.tenants.get_by_id = AsyncMock(return_value=None)

    # Act
    use_case = RestoreTenantUseCase(mock_uow, mock_audit_service)
    result = await use_case.execute(tenant_id)

    # Assert
    assert result.is_err()
    assert result.error.code == "TENANT_NOT_FOUND"
    mock_uow.commit.assert_not_called()


@pytest.mark.asyncio
async def test_restore_tenant_already_active(mock_uow, mock_audit_service):
    """Test restoring already-active tenant (idempotent)"""
    # Arrange
    tenant_id = uuid4()
    tenant = Tenant(id=tenant_id, name="Test Corp", status=TenantStatus.active)

    mock_uow.tenants.get_by_id = AsyncMock(return_value=tenant)
    mock_uow.tenants.update = AsyncMock(return_value=tenant)
    
    # Act
    use_case = RestoreTenantUseCase(mock_uow, mock_audit_service)
    result = await use_case.execute(tenant_id)

    # Assert
    assert result.is_ok()
    response = result.value
    assert response.status == "active"

    # Verify tenant status remains active
    assert tenant.status == TenantStatus.active
    mock_uow.commit.assert_called_once()
