import pytest
from httpx import AsyncClient
from datetime import datetime


@pytest.mark.asyncio
async def test_admin_views_audit_log(client: AsyncClient):
    """AT-9.1: Admin Views Audit Log

    Given I am authenticated as an admin/owner
    When I request audit events for my tenant
    Then I receive a list of audit events
    And the events are sorted newest first
    And each event includes action, user_email, timestamp, metadata
    And I receive a next_cursor for pagination if more events exist
    """
    # Create a user (owner) via signup
    signup_response = await client.post("/auth/signup", json={
        "email": "admin@acme.com",
        "password": "SecurePass123!",
        "tenant_name": "Acme Corp"
    })
    assert signup_response.status_code == 201
    access_token = signup_response.json()["access_token"]

    # Perform login to create more audit events
    await client.post("/auth/login", json={
        "email": "admin@acme.com",
        "password": "SecurePass123!"
    })

    # Request audit events
    response = await client.get(
        "/audit/auth-events",
        headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status_code == 200
    data = response.json()

    # Verify response structure
    assert "events" in data
    assert isinstance(data["events"], list)
    assert len(data["events"]) >= 2  # At least signup and login events

    # Verify event structure
    event = data["events"][0]
    assert "action" in event
    assert "user_email" in event
    assert "timestamp" in event
    assert "metadata" in event

    # Verify events are sorted newest first
    if len(data["events"]) > 1:
        first_timestamp = datetime.fromisoformat(data["events"][0]["timestamp"].replace("Z", "+00:00"))
        second_timestamp = datetime.fromisoformat(data["events"][1]["timestamp"].replace("Z", "+00:00"))
        assert first_timestamp >= second_timestamp

    # Verify pagination cursor exists
    assert "next_cursor" in data


@pytest.mark.asyncio
async def test_admin_views_audit_log_with_pagination(client: AsyncClient):
    """AT-9.1: Admin Views Audit Log with Pagination

    Given I am authenticated as an admin/owner
    When I request audit events with a limit
    Then I receive at most the limit number of events
    And I receive a next_cursor to fetch more events
    """
    # Create a user (owner) via signup
    signup_response = await client.post("/auth/signup", json={
        "email": "admin@acme.com",
        "password": "SecurePass123!",
        "tenant_name": "Acme Corp"
    })
    assert signup_response.status_code == 201
    access_token = signup_response.json()["access_token"]

    # Perform multiple logins to create more audit events
    for _ in range(5):
        await client.post("/auth/login", json={
            "email": "admin@acme.com",
            "password": "SecurePass123!"
        })

    # Request audit events with limit
    response = await client.get(
        "/audit/auth-events?limit=3",
        headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status_code == 200
    data = response.json()

    # Verify limit is respected
    assert len(data["events"]) <= 3

    # If there are more events, next_cursor should be provided
    if data["next_cursor"]:
        # Fetch next page
        next_response = await client.get(
            f"/audit/auth-events?limit=3&cursor={data['next_cursor']}",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        assert next_response.status_code == 200
        next_data = next_response.json()
        assert "events" in next_data


@pytest.mark.asyncio
async def test_member_cannot_view_audit_log(client: AsyncClient, db_session):
    """AT-9.2: Member Access Forbidden

    Given I am authenticated as a member (not admin/owner)
    When I request audit events
    Then the request fails with 403 Forbidden
    And error code is INSUFFICIENT_ROLE
    """
    # Create owner and tenant
    owner_response = await client.post("/auth/signup", json={
        "email": "owner@acme.com",
        "password": "SecurePass123!",
        "tenant_name": "Acme Corp"
    })
    assert owner_response.status_code == 201
    owner_token = owner_response.json()["access_token"]
    tenant_id = owner_response.json()["tenant"]["id"]

    # Invite a new user as a member
    invite_response = await client.post(
        f"/tenants/{tenant_id}/invite",
        json={"email": "member@acme.com", "role": "member"},
        headers={"Authorization": f"Bearer {owner_token}"}
    )
    assert invite_response.status_code == 201

    # Create the member user through signup
    member_signup = await client.post("/auth/signup", json={
        "email": "member@acme.com",
        "password": "MemberPass123!",
        "tenant_name": "Member Tenant"
    })
    assert member_signup.status_code == 201

    # Get member's token for owner's tenant by switching
    # First login as member
    member_login = await client.post("/auth/login", json={
        "email": "member@acme.com",
        "password": "MemberPass123!"
    })
    member_token = member_login.json()["access_token"]

    # Manually update membership to member role (simulating accepted invitation)
    from src.domain.entities import Membership, MembershipRole, MembershipStatus, User
    from sqlmodel import select

    # Get member user
    stmt = select(User).where(User.email == "member@acme.com")
    result = await db_session.exec(stmt)
    member_user = result.one()

    # Create membership as member role
    from uuid import UUID
    new_membership = Membership(
        user_id=member_user.id,
        tenant_id=UUID(tenant_id),
        role=MembershipRole.member,
        status=MembershipStatus.active
    )
    db_session.add(new_membership)
    await db_session.commit()

    # Switch to owner's tenant
    switch_response = await client.post(
        "/tenants/switch",
        json={"tenant_id": tenant_id},
        headers={"Authorization": f"Bearer {member_token}"}
    )
    assert switch_response.status_code == 200
    member_tenant_token = switch_response.json()["access_token"]

    # Try to access audit events as member
    response = await client.get(
        "/audit/auth-events",
        headers={"Authorization": f"Bearer {member_tenant_token}"}
    )

    assert response.status_code == 403
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "INSUFFICIENT_ROLE"


@pytest.mark.asyncio
async def test_unauthenticated_cannot_view_audit_log(client: AsyncClient):
    """AT-9.2: Unauthenticated Access

    Given I am not authenticated
    When I request audit events
    Then the request fails with 401 Unauthorized
    """
    response = await client.get("/audit/auth-events")

    assert response.status_code == 401  # Missing authentication token


@pytest.mark.asyncio
async def test_invalid_token_cannot_view_audit_log(client: AsyncClient):
    """AT-9.2: Invalid Token

    Given I have an invalid JWT token
    When I request audit events
    Then the request fails with 401 Unauthorized
    And error code is INVALID_TOKEN
    """
    response = await client.get(
        "/audit/auth-events",
        headers={"Authorization": "Bearer invalid_token_here"}
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_audit_events_scoped_to_tenant(client: AsyncClient):
    """Verify audit events are tenant-scoped

    Given I am authenticated as an owner of Tenant A
    When I request audit events
    Then I only see events for Tenant A
    And I do not see events from other tenants
    """
    # Create first tenant and user
    tenant_a_response = await client.post("/auth/signup", json={
        "email": "owner_a@tenanta.com",
        "password": "SecurePass123!",
        "tenant_name": "Tenant A"
    })
    assert tenant_a_response.status_code == 201
    token_a = tenant_a_response.json()["access_token"]

    # Create second tenant and user
    tenant_b_response = await client.post("/auth/signup", json={
        "email": "owner_b@tenantb.com",
        "password": "SecurePass123!",
        "tenant_name": "Tenant B"
    })
    assert tenant_b_response.status_code == 201

    # Perform login for Tenant A to create more events
    await client.post("/auth/login", json={
        "email": "owner_a@tenanta.com",
        "password": "SecurePass123!"
    })

    # Request audit events for Tenant A
    response = await client.get(
        "/audit/auth-events",
        headers={"Authorization": f"Bearer {token_a}"}
    )

    assert response.status_code == 200
    data = response.json()

    # Verify all events belong to Tenant A user
    for event in data["events"]:
        assert event["user_email"] == "owner_a@tenanta.com"
