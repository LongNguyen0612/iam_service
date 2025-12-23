"""
Integration tests for IAM-017: Suspend or Restore Tenant (Billing Integration)
Tests all acceptance criteria for tenant suspension and restoration.
"""

import pytest
from datetime import datetime, timedelta, UTC
from httpx import AsyncClient
from sqlmodel.ext.asyncio.session import AsyncSession
from uuid import UUID


@pytest.mark.asyncio
async def test_suspend_tenant_for_nonpayment(client: AsyncClient, db_session: AsyncSession):
    """
    AC-17.1: Suspend Tenant for Non-Payment

    Given a tenant's payment failed
    When the billing system calls suspend endpoint
    Then the Tenant.status is updated to suspended
    And all active Sessions for users in that tenant are revoked
    And new operations fail with TENANT_SUSPENDED
    And an AuditEvent with action=tenant_suspended is recorded
    """
    # Arrange: Create tenant with user
    signup_response = await client.post(
        "/auth/signup",
        json={
            "email": "owner@acme.com",
            "password": "SecurePass123!",
            "tenant_name": "Acme Corp",
        },
    )
    assert signup_response.status_code == 201
    tenant_id = signup_response.json()["tenant"]["id"]
    access_token = signup_response.json()["access_token"]

    # Verify tenant is active initially
    me_response = await client.get(
        "/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert me_response.status_code == 200
    assert me_response.json()["tenant"]["status"] == "active"

    # Act: Admin API suspends tenant (simulate billing system call)
    suspend_response = await client.post(
        f"/admin/tenants/{tenant_id}/suspend",
        headers={"X-Admin-API-Key": "test-admin-key-12345"},  # Admin API key auth
    )

    # Assert
    assert suspend_response.status_code == 200
    data = suspend_response.json()
    assert data["status"] == "suspended"
    assert data["sessions_revoked"] > 0  # At least signup session was revoked

    # Verify tenant status in database
    from src.domain.entities import Tenant
    from sqlmodel import select

    stmt = select(Tenant).where(Tenant.id == UUID(tenant_id))
    result = await db_session.exec(stmt)
    tenant = result.one()
    assert tenant.status.value == "suspended"

    # Verify all sessions revoked
    from src.domain.entities import Session

    stmt = select(Session).where(Session.tenant_id == UUID(tenant_id))
    result = await db_session.exec(stmt)
    sessions = result.all()
    for session in sessions:
        assert session.revoked is True

    # Verify suspended tenant cannot access /me
    me_after_suspend = await client.get(
        "/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert me_after_suspend.status_code == 403
    error = me_after_suspend.json()["error"]
    assert error["code"] == "TENANT_SUSPENDED"

    # Verify audit event created
    from src.domain.entities import AuditEvent

    stmt = (
        select(AuditEvent)
        .where(AuditEvent.action == "tenant_suspended")
        .where(AuditEvent.tenant_id == UUID(tenant_id))
    )
    result = await db_session.exec(stmt)
    audit = result.one()
    assert audit.action == "tenant_suspended"


@pytest.mark.asyncio
async def test_restore_tenant_after_payment(client: AsyncClient, db_session: AsyncSession):
    """
    AC-17.2: Restore Tenant After Payment

    Given a suspended tenant's payment is received
    When the billing system calls restore endpoint
    Then the Tenant.status is updated to active
    And users can log in and create new sessions
    And an AuditEvent with action=tenant_restored is recorded
    """
    # Arrange: Create and suspend tenant
    signup_response = await client.post(
        "/auth/signup",
        json={
            "email": "owner@restored.com",
            "password": "SecurePass123!",
            "tenant_name": "Restored Corp",
        },
    )
    tenant_id = signup_response.json()["tenant"]["id"]

    # Suspend tenant
    await client.post(
        f"/admin/tenants/{tenant_id}/suspend",
        headers={"X-Admin-API-Key": "test-admin-key-12345"},
    )

    # Verify tenant is suspended
    from src.domain.entities import Tenant
    from sqlmodel import select

    stmt = select(Tenant).where(Tenant.id == UUID(tenant_id))
    result = await db_session.exec(stmt)
    tenant = result.one()
    assert tenant.status.value == "suspended"

    # Act: Admin API restores tenant
    restore_response = await client.post(
        f"/admin/tenants/{tenant_id}/restore",
        headers={"X-Admin-API-Key": "test-admin-key-12345"},
    )

    # Assert
    assert restore_response.status_code == 200
    data = restore_response.json()
    assert data["status"] == "active"

    # Verify tenant status in database
    await db_session.refresh(tenant)
    assert tenant.status.value == "active"

    # Verify users can log in again
    login_response = await client.post(
        "/auth/login",
        json={"email": "owner@restored.com", "password": "SecurePass123!"},
    )
    assert login_response.status_code == 200
    new_token = login_response.json()["access_token"]

    # Verify /me works with new session
    me_response = await client.get(
        "/me",
        headers={"Authorization": f"Bearer {new_token}"},
    )
    assert me_response.status_code == 200
    assert me_response.json()["tenant"]["status"] == "active"

    # Verify audit event created
    from src.domain.entities import AuditEvent

    stmt = (
        select(AuditEvent)
        .where(AuditEvent.action == "tenant_restored")
        .where(AuditEvent.tenant_id == UUID(tenant_id))
    )
    result = await db_session.exec(stmt)
    audit = result.one()
    assert audit.action == "tenant_restored"


@pytest.mark.asyncio
async def test_suspended_tenant_cannot_perform_operations(
    client: AsyncClient, db_session: AsyncSession
):
    """
    AC-17.3: Suspended Tenant Cannot Perform Operations

    Given my tenant is suspended
    When I attempt to execute critical operations
    Then the request fails with 402 Payment Required or 403 Forbidden
    And error code is TENANT_SUSPENDED
    """
    # Arrange: Create tenant and get token before suspension
    signup_response = await client.post(
        "/auth/signup",
        json={
            "email": "user@blocked.com",
            "password": "SecurePass123!",
            "tenant_name": "Blocked Corp",
        },
    )
    tenant_id = signup_response.json()["tenant"]["id"]
    access_token = signup_response.json()["access_token"]

    # Suspend tenant
    await client.post(
        f"/admin/tenants/{tenant_id}/suspend",
        headers={"X-Admin-API-Key": "test-admin-key-12345"},
    )

    # Act & Assert: Try various operations with suspended tenant

    # 1. Cannot access /me
    me_response = await client.get(
        "/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert me_response.status_code == 403
    assert me_response.json()["error"]["code"] == "TENANT_SUSPENDED"

    # 2. Cannot switch tenants (if user had multiple)
    switch_response = await client.post(
        "/tenants/switch",
        json={"tenant_id": tenant_id},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert switch_response.status_code in [403, 401]  # Session revoked or tenant suspended

    # 3. Cannot view audit logs
    audit_response = await client.get(
        "/audit/auth-events",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert audit_response.status_code in [403, 401]


@pytest.mark.asyncio
async def test_admin_api_key_required(client: AsyncClient, db_session: AsyncSession):
    """
    Test that admin endpoints require valid API key

    When I call admin endpoints without API key
    Then the request fails with 401 Unauthorized
    """
    # Arrange: Create tenant
    signup_response = await client.post(
        "/auth/signup",
        json={
            "email": "owner@test.com",
            "password": "SecurePass123!",
            "tenant_name": "Test Corp",
        },
    )
    tenant_id = signup_response.json()["tenant"]["id"]

    # Act: Try to suspend without API key
    response = await client.post(f"/admin/tenants/{tenant_id}/suspend")

    # Assert
    assert response.status_code == 401
    error = response.json()["error"]
    assert error["code"] == "UNAUTHORIZED"


@pytest.mark.asyncio
async def test_admin_api_key_invalid(client: AsyncClient, db_session: AsyncSession):
    """
    Test that invalid admin API key is rejected
    """
    # Arrange: Create tenant
    signup_response = await client.post(
        "/auth/signup",
        json={
            "email": "owner@test.com",
            "password": "SecurePass123!",
            "tenant_name": "Test Corp",
        },
    )
    tenant_id = signup_response.json()["tenant"]["id"]

    # Act: Try with invalid API key
    response = await client.post(
        f"/admin/tenants/{tenant_id}/suspend",
        headers={"X-Admin-API-Key": "invalid-key"},
    )

    # Assert
    assert response.status_code == 401
    error = response.json()["error"]
    assert error["code"] == "INVALID_API_KEY"


@pytest.mark.asyncio
async def test_suspend_nonexistent_tenant(client: AsyncClient, db_session: AsyncSession):
    """
    Test suspending non-existent tenant returns 404
    """
    from uuid import uuid4

    fake_tenant_id = str(uuid4())

    response = await client.post(
        f"/admin/tenants/{fake_tenant_id}/suspend",
        headers={"X-Admin-API-Key": "test-admin-key-12345"},
    )

    assert response.status_code == 404
    error = response.json()["error"]
    assert error["code"] == "TENANT_NOT_FOUND"


@pytest.mark.asyncio
async def test_restore_nonexistent_tenant(client: AsyncClient, db_session: AsyncSession):
    """
    Test restoring non-existent tenant returns 404
    """
    from uuid import uuid4

    fake_tenant_id = str(uuid4())

    response = await client.post(
        f"/admin/tenants/{fake_tenant_id}/restore",
        headers={"X-Admin-API-Key": "test-admin-key-12345"},
    )

    assert response.status_code == 404
    error = response.json()["error"]
    assert error["code"] == "TENANT_NOT_FOUND"


@pytest.mark.asyncio
async def test_suspend_already_suspended_tenant(
    client: AsyncClient, db_session: AsyncSession
):
    """
    Test that suspending already suspended tenant is idempotent
    """
    # Arrange: Create and suspend tenant
    signup_response = await client.post(
        "/auth/signup",
        json={
            "email": "owner@test.com",
            "password": "SecurePass123!",
            "tenant_name": "Test Corp",
        },
    )
    tenant_id = signup_response.json()["tenant"]["id"]

    # First suspension
    response1 = await client.post(
        f"/admin/tenants/{tenant_id}/suspend",
        headers={"X-Admin-API-Key": "test-admin-key-12345"},
    )
    assert response1.status_code == 200

    # Act: Second suspension
    response2 = await client.post(
        f"/admin/tenants/{tenant_id}/suspend",
        headers={"X-Admin-API-Key": "test-admin-key-12345"},
    )

    # Assert: Should succeed but revoke 0 sessions
    assert response2.status_code == 200
    data = response2.json()
    assert data["status"] == "suspended"
    assert data["sessions_revoked"] == 0  # No active sessions to revoke


@pytest.mark.asyncio
async def test_restore_already_active_tenant(
    client: AsyncClient, db_session: AsyncSession
):
    """
    Test that restoring already active tenant is idempotent
    """
    # Arrange: Create active tenant
    signup_response = await client.post(
        "/auth/signup",
        json={
            "email": "owner@test.com",
            "password": "SecurePass123!",
            "tenant_name": "Test Corp",
        },
    )
    tenant_id = signup_response.json()["tenant"]["id"]

    # Act: Restore already active tenant
    response = await client.post(
        f"/admin/tenants/{tenant_id}/restore",
        headers={"X-Admin-API-Key": "test-admin-key-12345"},
    )

    # Assert: Should succeed
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "active"
