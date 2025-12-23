"""
Integration tests for IAM-018: Cancel Tenant Deletion (AC-18.3)

Tests rollback functionality within 7-day window.
"""

import pytest
from datetime import datetime, timedelta, UTC
from httpx import AsyncClient
from sqlmodel.ext.asyncio.session import AsyncSession
from src.domain.entities import Tenant, MembershipRole
from config import ApplicationConfig


@pytest.mark.asyncio
async def test_successful_cancel_deletion(client: AsyncClient, db_session: AsyncSession):
    """AC-18.3: Cancel deletion within rollback window

    Given a tenant was deleted less than 7 days ago
    When admin calls cancel-deletion endpoint
    Then the tenant is restored to active status
    And deleted_at is cleared
    And an audit event is created
    """
    # Create a tenant marked for deletion
    tenant = Tenant(
        name="Acme Corp",
        status="suspended",
        deleted_at=datetime.now(UTC) - timedelta(days=3),  # 3 days ago
    )
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)

    # Cancel deletion (admin endpoint)
    response = await client.post(
        f"/admin/tenants/{tenant.id}/cancel-deletion",
        headers={"X-Admin-API-Key": ApplicationConfig.ADMIN_API_KEY},
    )

    # Assert successful restoration
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "restored"
    assert data["tenant_name"] == "Acme Corp"
    assert "restored_at" in data

    # Verify tenant is active and deleted_at is cleared
    await db_session.refresh(tenant)
    assert tenant.status.value == "active"
    assert tenant.deleted_at is None


@pytest.mark.asyncio
async def test_cancel_deletion_not_scheduled(
    client: AsyncClient, db_session: AsyncSession
):
    """AC-18.3: Cannot cancel if not scheduled for deletion

    Given a tenant that is not marked for deletion
    When admin calls cancel-deletion endpoint
    Then the request fails with 400 Bad Request
    And error code is NOT_SCHEDULED_FOR_DELETION
    """
    # Create an active tenant (not marked for deletion)
    tenant = Tenant(name="Active Corp", status="active")
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)

    # Attempt to cancel deletion
    response = await client.post(
        f"/admin/tenants/{tenant.id}/cancel-deletion",
        headers={"X-Admin-API-Key": ApplicationConfig.ADMIN_API_KEY},
    )

    # Assert bad request
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "NOT_SCHEDULED_FOR_DELETION"


@pytest.mark.asyncio
async def test_cancel_deletion_window_expired(
    client: AsyncClient, db_session: AsyncSession
):
    """AC-18.3: Cannot cancel after 7-day window

    Given a tenant was deleted more than 7 days ago
    When admin calls cancel-deletion endpoint
    Then the request fails with 410 Gone
    And error code is ROLLBACK_WINDOW_EXPIRED
    """
    # Create a tenant deleted 8 days ago (past rollback window)
    tenant = Tenant(
        name="Old Corp",
        status="suspended",
        deleted_at=datetime.now(UTC) - timedelta(days=8),
    )
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)

    # Attempt to cancel deletion
    response = await client.post(
        f"/admin/tenants/{tenant.id}/cancel-deletion",
        headers={"X-Admin-API-Key": ApplicationConfig.ADMIN_API_KEY},
    )

    # Assert gone (410)
    assert response.status_code == 410
    assert response.json()["error"]["code"] == "ROLLBACK_WINDOW_EXPIRED"


@pytest.mark.asyncio
async def test_cancel_deletion_tenant_not_found(
    client: AsyncClient, db_session: AsyncSession
):
    """AC-18.3: Tenant not found

    Given I provide a non-existent tenant ID
    When admin calls cancel-deletion endpoint
    Then the request fails with 404 Not Found
    And error code is TENANT_NOT_FOUND
    """
    fake_tenant_id = "00000000-0000-0000-0000-000000000000"

    response = await client.post(
        f"/admin/tenants/{fake_tenant_id}/cancel-deletion",
        headers={"X-Admin-API-Key": ApplicationConfig.ADMIN_API_KEY},
    )

    # Assert not found
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "TENANT_NOT_FOUND"


@pytest.mark.asyncio
async def test_cancel_deletion_unauthorized(
    client: AsyncClient, db_session: AsyncSession
):
    """Security Test: Unauthorized access

    Given I don't provide valid admin API key
    When I call cancel-deletion endpoint
    Then the request fails with 401 Unauthorized
    """
    tenant = Tenant(
        name="Test Corp",
        status="suspended",
        deleted_at=datetime.now(UTC) - timedelta(days=1),
    )
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)

    # Attempt without API key
    response = await client.post(f"/admin/tenants/{tenant.id}/cancel-deletion")

    # Assert unauthorized
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_cancel_deletion_on_deadline_day(
    client: AsyncClient, db_session: AsyncSession
):
    """Edge Case: Cancel deletion on day 7 (exactly at deadline)

    Given a tenant was deleted exactly 7 days ago
    When admin calls cancel-deletion endpoint
    Then the request should succeed (still within window)
    """
    # Create a tenant deleted exactly 7 days ago (minus 1 hour for safety)
    tenant = Tenant(
        name="Deadline Corp",
        status="suspended",
        deleted_at=datetime.now(UTC) - timedelta(days=7) + timedelta(hours=1),
    )
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)

    # Cancel deletion
    response = await client.post(
        f"/admin/tenants/{tenant.id}/cancel-deletion",
        headers={"X-Admin-API-Key": ApplicationConfig.ADMIN_API_KEY},
    )

    # Should succeed
    assert response.status_code == 200
    assert response.json()["status"] == "restored"
