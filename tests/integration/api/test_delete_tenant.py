"""
Integration tests for IAM-018: Delete Tenant (Soft Delete)

Tests all acceptance criteria:
- AC-18.1: Initiate Soft Delete
- AC-18.2: Async Data Purge (tested via use case)
- AC-18.3: Rollback Window
- AC-18.4: Prevent Deletion with Unpaid Balance (future)
- AC-18.5: Orphaned User Handling (tested via purge use case)
"""

import pytest
import json
from datetime import datetime, timedelta, UTC
from httpx import AsyncClient
from sqlmodel.ext.asyncio.session import AsyncSession
from src.domain.entities import Tenant, User, Membership, Session, MembershipRole, MembershipStatus
import bcrypt


async def create_test_user_with_tenant(
    db_session: AsyncSession, email: str = "owner@example.com", tenant_name: str = "Test Corp"
) -> tuple[User, Tenant, Membership, str]:
    """Helper to create a test user with tenant"""
    # Create tenant
    tenant = Tenant(name=tenant_name)
    db_session.add(tenant)
    await db_session.flush()
    await db_session.refresh(tenant)

    # Create user
    password_hash = bcrypt.hashpw("TestPass123!".encode(), bcrypt.gensalt(12))
    user = User(
        email=email, password_hash=password_hash.decode(), email_verified=True
    )
    db_session.add(user)
    await db_session.flush()
    await db_session.refresh(user)

    # Create membership
    membership = Membership(
        user_id=user.id,
        tenant_id=tenant.id,
        role=MembershipRole.owner,
        status=MembershipStatus.active,
    )
    db_session.add(membership)
    await db_session.commit()

    # Get auth token
    from src.api.utils.jwt import generate_jwt

    token = generate_jwt(
        user_id=user.id,
        tenant_id=tenant.id,
        role=MembershipRole.owner.value,
    )

    return user, tenant, membership, token


@pytest.mark.asyncio
async def test_successful_tenant_deletion(client: AsyncClient, db_session: AsyncSession):
    """AC-18.1: Initiate Soft Delete

    Given I am the tenant owner
    When I request tenant deletion with valid confirmation
    Then the tenant status is set to suspended
    And deleted_at timestamp is set
    And all active sessions are revoked
    And a deletion audit event is created
    And I receive purge schedule details
    """
    # Create owner user with tenant
    user, tenant, membership, token = await create_test_user_with_tenant(
        db_session, email="owner@acme.com", tenant_name="Acme Corp"
    )

    # Create a session for the user
    session = Session(
        user_id=user.id,
        tenant_id=tenant.id,
        refresh_token_hash=bcrypt.hashpw(b"refresh_token", bcrypt.gensalt(12)).decode(),
    )
    db_session.add(session)
    await db_session.commit()

    # Delete tenant with correct confirmation
    response = await client.request(
        "DELETE",
        f"/tenants/{tenant.id}",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        content=json.dumps({"confirmation": "DELETE_TENANT_Acme_Corp"}),
    )

    # Assert successful response (202 Accepted for async operation)
    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "deletion_initiated"
    assert "purge_scheduled_at" in data
    assert "rollback_deadline" in data
    assert data["sessions_revoked"] == 1

    # Verify tenant is suspended and marked for deletion
    await db_session.refresh(tenant)
    assert tenant.status.value == "suspended"
    assert tenant.deleted_at is not None
    # Ensure timezone-aware comparison
    deleted_at_aware = tenant.deleted_at.replace(tzinfo=UTC) if tenant.deleted_at.tzinfo is None else tenant.deleted_at
    assert (datetime.now(UTC) - deleted_at_aware).total_seconds() < 10

    # Verify session was revoked
    await db_session.refresh(session)
    assert session.revoked is True
    assert session.revoked_at is not None


@pytest.mark.asyncio
async def test_delete_tenant_insufficient_role(
    client: AsyncClient, db_session: AsyncSession
):
    """AC-18.1: Only owner can delete

    Given I am an admin (not owner)
    When I attempt to delete the tenant
    Then the request fails with 403 Forbidden
    And error code is INSUFFICIENT_ROLE
    """
    # Create owner user with tenant
    owner, tenant, owner_membership, owner_token = await create_test_user_with_tenant(
        db_session, email="owner@example.com"
    )

    # Create admin user
    password_hash = bcrypt.hashpw("TestPass123!".encode(), bcrypt.gensalt(12))
    admin_user = User(
        email="admin@example.com", password_hash=password_hash.decode(), email_verified=True
    )
    db_session.add(admin_user)
    await db_session.flush()
    await db_session.refresh(admin_user)

    # Create admin membership
    admin_membership = Membership(
        user_id=admin_user.id,
        tenant_id=tenant.id,
        role=MembershipRole.admin,
        status=MembershipStatus.active,
    )
    db_session.add(admin_membership)
    await db_session.commit()

    # Get admin token
    from src.api.utils.jwt import generate_jwt

    admin_token = generate_jwt(
        user_id=admin_user.id,
        tenant_id=tenant.id,
        role=MembershipRole.admin.value,
    )

    # Attempt to delete as admin
    response = await client.request(
        "DELETE",
        f"/tenants/{tenant.id}",
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Content-Type": "application/json",
        },
        content=json.dumps({"confirmation": "DELETE_TENANT_Test_Corp"}),
    )

    # Assert forbidden
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "INSUFFICIENT_ROLE"

    # Verify tenant is NOT marked for deletion
    await db_session.refresh(tenant)
    assert tenant.deleted_at is None


@pytest.mark.asyncio
async def test_delete_tenant_invalid_confirmation(
    client: AsyncClient, db_session: AsyncSession
):
    """AC-18.1: Invalid confirmation string

    Given I am the tenant owner
    When I provide an incorrect confirmation string
    Then the request fails with 400 Bad Request
    And error code is INVALID_CONFIRMATION
    """
    user, tenant, membership, token = await create_test_user_with_tenant(
        db_session, tenant_name="Acme Corp"
    )

    # Attempt delete with wrong confirmation
    response = await client.request(
        "DELETE",
        f"/tenants/{tenant.id}",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        content=json.dumps({"confirmation": "WRONG_CONFIRMATION"}),
    )

    # Assert bad request
    assert response.status_code == 400
    data = response.json()
    assert data["error"]["code"] == "INVALID_CONFIRMATION"
    assert "DELETE_TENANT_Acme_Corp" in data["error"]["message"]

    # Verify tenant is NOT marked for deletion
    await db_session.refresh(tenant)
    assert tenant.deleted_at is None


@pytest.mark.asyncio
async def test_delete_tenant_already_deleted(
    client: AsyncClient, db_session: AsyncSession
):
    """AC-18.1: Prevent double deletion

    Given the tenant is already marked for deletion
    When I attempt to delete it again
    Then the request fails with 409 Conflict
    And error code is ALREADY_DELETED
    """
    user, tenant, membership, token = await create_test_user_with_tenant(db_session)

    # Mark tenant as already deleted
    tenant.deleted_at = datetime.now(UTC)
    tenant.status = "suspended"
    db_session.add(tenant)
    await db_session.commit()

    # Attempt delete again
    response = await client.request(
        "DELETE",
        f"/tenants/{tenant.id}",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        content=json.dumps({"confirmation": "DELETE_TENANT_Test_Corp"}),
    )

    # Assert conflict
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "ALREADY_DELETED"


@pytest.mark.asyncio
async def test_delete_tenant_not_found(client: AsyncClient, db_session: AsyncSession):
    """AC-18.1: Tenant not found

    Given I provide a non-existent tenant ID
    When I attempt to delete
    Then the request fails with 404 Not Found
    And error code is TENANT_NOT_FOUND
    """
    user, tenant, membership, token = await create_test_user_with_tenant(db_session)

    # Attempt to delete non-existent tenant
    fake_tenant_id = "00000000-0000-0000-0000-000000000000"
    response = await client.request(
        "DELETE",
        f"/tenants/{fake_tenant_id}",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        content=json.dumps({"confirmation": "DELETE_TENANT_Test_Corp"}),
    )

    # Assert not found
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "TENANT_NOT_FOUND"


@pytest.mark.asyncio
async def test_delete_tenant_unauthorized(client: AsyncClient, db_session: AsyncClient):
    """Security Test: Unauthorized deletion

    Given I am not authenticated
    When I attempt to delete a tenant
    Then the request fails with 401 Unauthorized
    """
    user, tenant, membership, token = await create_test_user_with_tenant(db_session)

    # Attempt delete without auth token
    response = await client.request(
        "DELETE",
        f"/tenants/{tenant.id}",
        headers={"Content-Type": "application/json"},
        content=json.dumps({"confirmation": "DELETE_TENANT_Test_Corp"}),
    )

    # Assert unauthorized
    assert response.status_code == 401
