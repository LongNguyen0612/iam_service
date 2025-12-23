import pytest
from httpx import AsyncClient
from uuid import UUID


@pytest.mark.asyncio
async def test_successful_role_change(client: AsyncClient, db_session):
    """AC-7.1: Successful Role Change

    Given I am the tenant owner
    When I update a member's role to a valid role
    Then the Membership.role is updated
    And an AuditEvent with action=role_changed is recorded
    And the user's existing JWT remains valid until expiry
    """
    # Create tenant owner
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

    # Create a second user (member)
    signup_response2 = await client.post(
        "/auth/signup",
        json={
            "email": "member@acme.com",
            "password": "SecurePass123!",
            "tenant_name": "Member Corp",
        },
    )
    assert signup_response2.status_code == 201

    # Add member to first tenant as "member" role
    from src.domain.entities import Membership, MembershipRole, MembershipStatus, User
    from sqlmodel import select

    stmt = select(User).where(User.email == "member@acme.com")
    result = await db_session.exec(stmt)
    member_user = result.one()

    membership = Membership(
        user_id=member_user.id,
        tenant_id=UUID(tenant_id),
        role=MembershipRole.member,
        status=MembershipStatus.active,
    )
    db_session.add(membership)
    await db_session.commit()

    # Login as owner
    login_response = await client.post(
        "/auth/login",
        json={"email": "owner@acme.com", "password": "SecurePass123!"},
    )
    assert login_response.status_code == 200
    access_token = login_response.json()["access_token"]

    # Change member's role to admin
    response = await client.put(
        f"/tenants/{tenant_id}/members/{str(member_user.id)}",
        json={"role": "admin"},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 200
    data = response.json()

    # Verify response
    assert data["status"] == "updated"
    assert data["membership"]["user_id"] == str(member_user.id)
    assert data["membership"]["role"] == "admin"

    # Verify membership was updated in database
    await db_session.refresh(membership)
    assert membership.role == MembershipRole.admin

    # Verify audit event was created
    from src.domain.entities import AuditEvent

    stmt = select(AuditEvent).where(AuditEvent.action == "role_changed")
    result = await db_session.exec(stmt)
    audit_events = result.all()
    assert len(audit_events) == 1
    assert audit_events[0].event_metadata["target_user_id"] == str(member_user.id)
    assert audit_events[0].event_metadata["old_role"] == "member"
    assert audit_events[0].event_metadata["new_role"] == "admin"


@pytest.mark.asyncio
async def test_owner_demotes_self(client: AsyncClient):
    """AC-7.2: Owner Demotes Self

    Given I am the owner
    When I attempt to demote myself
    Then the request fails with 409 Conflict
    And error code is CANNOT_DEMOTE_SELF
    """
    # Create tenant owner
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
    owner_user_id = signup_response.json()["user"]["id"]

    # Login as owner
    login_response = await client.post(
        "/auth/login",
        json={"email": "owner@acme.com", "password": "SecurePass123!"},
    )
    assert login_response.status_code == 200
    access_token = login_response.json()["access_token"]

    # Try to demote self to admin
    response = await client.put(
        f"/tenants/{tenant_id}/members/{owner_user_id}",
        json={"role": "admin"},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 409
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "CANNOT_DEMOTE_SELF"


@pytest.mark.asyncio
async def test_membership_not_found(client: AsyncClient):
    """AC-7.3: Membership Not Found

    Given the target user is not a member of my tenant
    When I attempt to change their role
    Then the request fails with 404 Not Found
    And error code is MEMBERSHIP_NOT_FOUND
    """
    # Create tenant owner
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

    # Create a second user (not a member of first tenant)
    signup_response2 = await client.post(
        "/auth/signup",
        json={
            "email": "other@example.com",
            "password": "SecurePass123!",
            "tenant_name": "Other Corp",
        },
    )
    assert signup_response2.status_code == 201
    other_user_id = signup_response2.json()["user"]["id"]

    # Login as owner
    login_response = await client.post(
        "/auth/login",
        json={"email": "owner@acme.com", "password": "SecurePass123!"},
    )
    assert login_response.status_code == 200
    access_token = login_response.json()["access_token"]

    # Try to change role of non-member
    response = await client.put(
        f"/tenants/{tenant_id}/members/{other_user_id}",
        json={"role": "admin"},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 404
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "MEMBERSHIP_NOT_FOUND"


@pytest.mark.asyncio
async def test_invalid_role(client: AsyncClient, db_session):
    """AC-7.4: Invalid Role

    Given I specify an invalid role
    When I attempt to update
    Then the request fails with 400 Bad Request
    And error code is INVALID_ROLE
    """
    # Create tenant owner
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

    # Create a second user (member)
    signup_response2 = await client.post(
        "/auth/signup",
        json={
            "email": "member@acme.com",
            "password": "SecurePass123!",
            "tenant_name": "Member Corp",
        },
    )
    assert signup_response2.status_code == 201
    member_user_id = signup_response2.json()["user"]["id"]

    # Add member to first tenant
    from src.domain.entities import Membership, MembershipRole, MembershipStatus, User
    from sqlmodel import select

    stmt = select(User).where(User.email == "member@acme.com")
    result = await db_session.exec(stmt)
    member_user = result.one()

    membership = Membership(
        user_id=member_user.id,
        tenant_id=UUID(tenant_id),
        role=MembershipRole.member,
        status=MembershipStatus.active,
    )
    db_session.add(membership)
    await db_session.commit()

    # Login as owner
    login_response = await client.post(
        "/auth/login",
        json={"email": "owner@acme.com", "password": "SecurePass123!"},
    )
    assert login_response.status_code == 200
    access_token = login_response.json()["access_token"]

    # Try to change role to invalid role
    response = await client.put(
        f"/tenants/{tenant_id}/members/{member_user_id}",
        json={"role": "superadmin"},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 400
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "INVALID_ROLE"


@pytest.mark.asyncio
async def test_non_owner_cannot_change_role(client: AsyncClient, db_session):
    """Verify that non-owners (admins/members) cannot change roles

    Given I am an admin or member (not owner)
    When I attempt to change a role
    Then the request fails with 403 Forbidden
    And error code is INSUFFICIENT_ROLE
    """
    # Create tenant owner
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

    # Create an admin user
    signup_response2 = await client.post(
        "/auth/signup",
        json={
            "email": "admin@acme.com",
            "password": "SecurePass123!",
            "tenant_name": "Admin Corp",
        },
    )
    assert signup_response2.status_code == 201

    # Create a member user
    signup_response3 = await client.post(
        "/auth/signup",
        json={
            "email": "member@acme.com",
            "password": "SecurePass123!",
            "tenant_name": "Member Corp",
        },
    )
    assert signup_response3.status_code == 201
    member_user_id = signup_response3.json()["user"]["id"]

    # Add admin to first tenant as "admin" role
    from src.domain.entities import Membership, MembershipRole, MembershipStatus, User
    from sqlmodel import select

    stmt = select(User).where(User.email == "admin@acme.com")
    result = await db_session.exec(stmt)
    admin_user = result.one()

    admin_membership = Membership(
        user_id=admin_user.id,
        tenant_id=UUID(tenant_id),
        role=MembershipRole.admin,
        status=MembershipStatus.active,
    )
    db_session.add(admin_membership)

    # Add member to first tenant
    stmt = select(User).where(User.email == "member@acme.com")
    result = await db_session.exec(stmt)
    member_user = result.one()

    member_membership = Membership(
        user_id=member_user.id,
        tenant_id=UUID(tenant_id),
        role=MembershipRole.member,
        status=MembershipStatus.active,
    )
    db_session.add(member_membership)
    await db_session.commit()

    # Login as admin
    login_response = await client.post(
        "/auth/login",
        json={"email": "admin@acme.com", "password": "SecurePass123!"},
    )
    assert login_response.status_code == 200
    access_token = login_response.json()["access_token"]

    # Try to change member's role as admin (should fail)
    response = await client.put(
        f"/tenants/{tenant_id}/members/{member_user_id}",
        json={"role": "admin"},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 403
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "INSUFFICIENT_ROLE"


@pytest.mark.asyncio
async def test_owner_can_keep_own_role(client: AsyncClient):
    """Verify that owner can "change" their role to owner (no-op)

    Given I am the owner
    When I update my role to owner
    Then the request succeeds
    """
    # Create tenant owner
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
    owner_user_id = signup_response.json()["user"]["id"]

    # Login as owner
    login_response = await client.post(
        "/auth/login",
        json={"email": "owner@acme.com", "password": "SecurePass123!"},
    )
    assert login_response.status_code == 200
    access_token = login_response.json()["access_token"]

    # Change own role to owner (no-op, should succeed)
    response = await client.put(
        f"/tenants/{tenant_id}/members/{owner_user_id}",
        json={"role": "owner"},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "updated"
    assert data["membership"]["role"] == "owner"
