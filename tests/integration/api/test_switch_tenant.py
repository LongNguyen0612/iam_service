import pytest
from httpx import AsyncClient
from uuid import UUID, uuid4


@pytest.mark.asyncio
async def test_successful_tenant_switch(client: AsyncClient, db_session):
    """AC-5.1: Successful Tenant Switch

    Given a user is a member of multiple tenants
    When I submit a switch request to a tenant where I have active membership
    Then I receive a new JWT scoped to the target tenant
    And my User.last_active_tenant_id is updated
    And an AuditEvent with action=tenant_switch is recorded
    """
    # Create first user (will own first tenant)
    signup_response = await client.post(
        "/auth/signup",
        json={
            "email": "owner@acme.com",
            "password": "SecurePass123!",
            "tenant_name": "Acme Corp",
        },
    )
    assert signup_response.status_code == 201
    first_tenant_id = signup_response.json()["tenant"]["id"]

    # Create second tenant by creating another user
    signup_response2 = await client.post(
        "/auth/signup",
        json={
            "email": "owner2@beta.com",
            "password": "SecurePass123!",
            "tenant_name": "Beta Inc",
        },
    )
    assert signup_response2.status_code == 201
    second_tenant_id = signup_response2.json()["tenant"]["id"]

    # Get the first user and add them to the second tenant
    from src.domain.entities import Membership, MembershipRole, MembershipStatus, User
    from sqlmodel import select

    stmt = select(User).where(User.email == "owner@acme.com")
    result = await db_session.exec(stmt)
    user = result.one()

    # Create membership in second tenant
    new_membership = Membership(
        user_id=user.id,
        tenant_id=UUID(second_tenant_id),
        role=MembershipRole.member,
        status=MembershipStatus.active,
    )
    db_session.add(new_membership)
    await db_session.commit()

    # Login as first user
    login_response = await client.post(
        "/auth/login",
        json={"email": "owner@acme.com", "password": "SecurePass123!"},
    )
    assert login_response.status_code == 200
    access_token = login_response.json()["access_token"]

    # Now switch to second tenant
    response = await client.post(
        "/tenants/switch",
        json={"tenant_id": second_tenant_id},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 200
    data = response.json()

    # Verify new access token is returned
    assert "access_token" in data
    assert isinstance(data["access_token"], str)
    assert len(data["access_token"]) > 0

    # Verify tenant info - should now be Beta Inc
    assert "tenant" in data
    assert data["tenant"]["id"] == second_tenant_id
    assert data["tenant"]["name"] == "Beta Inc"
    assert data["tenant"]["role"] == "member"

    # Verify user.last_active_tenant_id was updated to second tenant
    await db_session.refresh(user)
    assert str(user.last_active_tenant_id) == second_tenant_id

    # Verify audit event was created
    from src.domain.entities import AuditEvent

    stmt = select(AuditEvent).where(AuditEvent.action == "tenant_switch")
    result = await db_session.exec(stmt)
    audit_events = result.all()
    assert len(audit_events) == 1
    assert audit_events[0].user_id == user.id
    assert str(audit_events[0].tenant_id) == second_tenant_id


@pytest.mark.asyncio
async def test_switch_tenant_not_a_member(client: AsyncClient):
    """AC-5.2: User Not a Member

    Given a user is not a member of the target tenant
    When I submit a switch request
    Then the request fails with 403 Forbidden
    And error code is NOT_A_MEMBER
    """
    # Create first user
    signup_response = await client.post(
        "/auth/signup",
        json={
            "email": "user@acme.com",
            "password": "SecurePass123!",
            "tenant_name": "Acme Corp",
        },
    )
    assert signup_response.status_code == 201

    # Create second tenant (different user)
    signup_response2 = await client.post(
        "/auth/signup",
        json={
            "email": "user2@beta.com",
            "password": "SecurePass123!",
            "tenant_name": "Beta Inc",
        },
    )
    assert signup_response2.status_code == 201
    second_tenant_id = signup_response2.json()["tenant"]["id"]

    # Login as first user
    login_response = await client.post(
        "/auth/login",
        json={"email": "user@acme.com", "password": "SecurePass123!"},
    )
    assert login_response.status_code == 200
    access_token = login_response.json()["access_token"]

    # Try to switch to second tenant (user is not a member)
    response = await client.post(
        "/tenants/switch",
        json={"tenant_id": second_tenant_id},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 403
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "NOT_A_MEMBER"


@pytest.mark.asyncio
async def test_switch_tenant_membership_revoked(client: AsyncClient, db_session):
    """AC-5.3: Membership Revoked

    Given a user's membership in the target tenant has been revoked
    When I submit a switch request
    Then the request fails with 403 Forbidden
    And error code is MEMBERSHIP_REVOKED
    """
    # Create first user
    signup_response = await client.post(
        "/auth/signup",
        json={
            "email": "user@acme.com",
            "password": "SecurePass123!",
            "tenant_name": "Acme Corp",
        },
    )
    assert signup_response.status_code == 201
    first_tenant_id = signup_response.json()["tenant"]["id"]

    # Create second tenant
    signup_response2 = await client.post(
        "/auth/signup",
        json={
            "email": "owner2@beta.com",
            "password": "SecurePass123!",
            "tenant_name": "Beta Inc",
        },
    )
    assert signup_response2.status_code == 201
    second_tenant_id = signup_response2.json()["tenant"]["id"]

    # Get the first user and add them to the second tenant
    from src.domain.entities import Membership, MembershipRole, MembershipStatus, User
    from sqlmodel import select

    stmt = select(User).where(User.email == "user@acme.com")
    result = await db_session.exec(stmt)
    user = result.one()

    # Create membership in second tenant (but mark it as revoked)
    revoked_membership = Membership(
        user_id=user.id,
        tenant_id=UUID(second_tenant_id),
        role=MembershipRole.member,
        status=MembershipStatus.revoked,
    )
    db_session.add(revoked_membership)
    await db_session.commit()

    # Login as first user
    login_response = await client.post(
        "/auth/login",
        json={"email": "user@acme.com", "password": "SecurePass123!"},
    )
    assert login_response.status_code == 200
    access_token = login_response.json()["access_token"]

    # Try to switch to second tenant (membership is revoked)
    response = await client.post(
        "/tenants/switch",
        json={"tenant_id": second_tenant_id},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 403
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "MEMBERSHIP_REVOKED"


@pytest.mark.asyncio
async def test_switch_tenant_suspended(client: AsyncClient, db_session):
    """AC-5.4: Tenant Suspended

    Given a tenant is suspended
    When I submit a switch request to that tenant
    Then the request fails with 403 Forbidden
    And error code is TENANT_SUSPENDED
    """
    # Create first user
    signup_response = await client.post(
        "/auth/signup",
        json={
            "email": "user@acme.com",
            "password": "SecurePass123!",
            "tenant_name": "Acme Corp",
        },
    )
    assert signup_response.status_code == 201

    # Create second tenant
    signup_response2 = await client.post(
        "/auth/signup",
        json={
            "email": "owner2@beta.com",
            "password": "SecurePass123!",
            "tenant_name": "Beta Inc",
        },
    )
    assert signup_response2.status_code == 201
    second_tenant_id = signup_response2.json()["tenant"]["id"]

    # Get the first user and add them to the second tenant
    from src.domain.entities import Membership, MembershipRole, MembershipStatus, Tenant, TenantStatus, User
    from sqlmodel import select

    stmt = select(User).where(User.email == "user@acme.com")
    result = await db_session.exec(stmt)
    user = result.one()

    # Create active membership in second tenant
    new_membership = Membership(
        user_id=user.id,
        tenant_id=UUID(second_tenant_id),
        role=MembershipRole.member,
        status=MembershipStatus.active,
    )
    db_session.add(new_membership)

    # Suspend the second tenant
    stmt = select(Tenant).where(Tenant.id == UUID(second_tenant_id))
    result = await db_session.exec(stmt)
    tenant = result.one()
    tenant.status = TenantStatus.suspended
    db_session.add(tenant)
    await db_session.commit()

    # Login as first user
    login_response = await client.post(
        "/auth/login",
        json={"email": "user@acme.com", "password": "SecurePass123!"},
    )
    assert login_response.status_code == 200
    access_token = login_response.json()["access_token"]

    # Try to switch to suspended tenant
    response = await client.post(
        "/tenants/switch",
        json={"tenant_id": second_tenant_id},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 403
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "TENANT_SUSPENDED"


@pytest.mark.asyncio
async def test_switch_tenant_invalid_tenant_id(client: AsyncClient):
    """Invalid Tenant ID Format

    Given I provide an invalid UUID format
    When I submit a switch request
    Then the request fails with 400 Bad Request
    And error code is INVALID_TENANT_ID
    """
    # Create and login as user
    signup_response = await client.post(
        "/auth/signup",
        json={
            "email": "user@acme.com",
            "password": "SecurePass123!",
            "tenant_name": "Acme Corp",
        },
    )
    assert signup_response.status_code == 201

    login_response = await client.post(
        "/auth/login",
        json={"email": "user@acme.com", "password": "SecurePass123!"},
    )
    assert login_response.status_code == 200
    access_token = login_response.json()["access_token"]

    # Try to switch with invalid tenant ID
    response = await client.post(
        "/tenants/switch",
        json={"tenant_id": "invalid-uuid"},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 400
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "INVALID_TENANT_ID"


@pytest.mark.asyncio
async def test_switch_tenant_nonexistent_tenant(client: AsyncClient):
    """Tenant Not Found

    Given a valid UUID that doesn't exist in the database
    When I submit a switch request
    Then the request fails with 404 Not Found
    And error code is TENANT_NOT_FOUND
    """
    # Create and login as user
    signup_response = await client.post(
        "/auth/signup",
        json={
            "email": "user@acme.com",
            "password": "SecurePass123!",
            "tenant_name": "Acme Corp",
        },
    )
    assert signup_response.status_code == 201

    login_response = await client.post(
        "/auth/login",
        json={"email": "user@acme.com", "password": "SecurePass123!"},
    )
    assert login_response.status_code == 200
    access_token = login_response.json()["access_token"]

    # Try to switch to non-existent tenant
    nonexistent_tenant_id = str(uuid4())
    response = await client.post(
        "/tenants/switch",
        json={"tenant_id": nonexistent_tenant_id},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 404
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "TENANT_NOT_FOUND"


@pytest.mark.asyncio
async def test_switch_tenant_unauthorized(client: AsyncClient):
    """Unauthorized Request (No JWT)

    Given I don't provide a JWT token
    When I submit a switch request
    Then the request fails with 401 Unauthorized
    """
    # Create a tenant (just to have a valid ID)
    signup_response = await client.post(
        "/auth/signup",
        json={
            "email": "user@acme.com",
            "password": "SecurePass123!",
            "tenant_name": "Acme Corp",
        },
    )
    assert signup_response.status_code == 201
    tenant_id = signup_response.json()["tenant"]["id"]

    # Try to switch without providing auth token
    response = await client.post(
        "/tenants/switch",
        json={"tenant_id": tenant_id},
    )

    assert response.status_code == 401
