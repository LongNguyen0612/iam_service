import pytest
from httpx import AsyncClient
from uuid import UUID
from datetime import UTC, datetime, timedelta


@pytest.mark.asyncio
async def test_successful_invite(client: AsyncClient, db_session):
    """AC-6.1: Successful Invite

    Given I am an owner or admin
    When I invite a user with valid email and role
    Then an Invitation is created with status=pending
    And the invitation expires in 7 days
    And an AuditEvent with action=invite_sent is recorded
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

    # Login as owner
    login_response = await client.post(
        "/auth/login",
        json={"email": "owner@acme.com", "password": "SecurePass123!"},
    )
    assert login_response.status_code == 200
    access_token = login_response.json()["access_token"]

    # Invite a user
    response = await client.post(
        f"/tenants/{tenant_id}/invite",
        json={"email": "newuser@example.com", "role": "member"},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 201
    data = response.json()

    # Verify response structure
    assert "invite_id" in data
    assert "status" in data
    assert "expires_at" in data
    assert data["status"] == "pending"

    # Verify invitation in database
    from src.domain.entities import Invitation
    from sqlmodel import select

    stmt = select(Invitation).where(Invitation.id == UUID(data["invite_id"]))
    result = await db_session.exec(stmt)
    invitation = result.one()

    assert invitation.email == "newuser@example.com"
    assert invitation.role.value == "member"
    assert invitation.status.value == "pending"
    assert str(invitation.tenant_id) == tenant_id

    # Verify expiration is ~7 days from now (allow for slight time drift)
    # invitation.expires_at is timezone-aware, compare with UTC time
    now_utc = datetime.now(UTC)
    expected_expiry = now_utc + timedelta(days=7)

    # Make invitation.expires_at timezone-aware if it's naive
    if invitation.expires_at.tzinfo is None:
        from datetime import timezone
        invitation_expires_aware = invitation.expires_at.replace(tzinfo=timezone.utc)
    else:
        invitation_expires_aware = invitation.expires_at

    time_diff = abs((invitation_expires_aware - expected_expiry).total_seconds())
    assert time_diff < 10  # Within 10 seconds

    # Verify audit event was created
    from src.domain.entities import AuditEvent

    stmt = select(AuditEvent).where(AuditEvent.action == "invite_sent")
    result = await db_session.exec(stmt)
    audit_events = result.all()
    assert len(audit_events) == 1
    assert audit_events[0].event_metadata["invited_email"] == "newuser@example.com"
    assert audit_events[0].event_metadata["role"] == "member"


@pytest.mark.asyncio
async def test_insufficient_role(client: AsyncClient, db_session):
    """AC-6.2: Insufficient Role

    Given I am a member (not admin/owner)
    When I attempt to send an invite
    Then the request fails with 403 Forbidden
    And error code is INSUFFICIENT_ROLE
    """
    # Create first tenant with owner
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

    # Login as member
    login_response = await client.post(
        "/auth/login",
        json={"email": "member@acme.com", "password": "SecurePass123!"},
    )
    assert login_response.status_code == 200
    access_token = login_response.json()["access_token"]

    # Try to invite a user (should fail)
    response = await client.post(
        f"/tenants/{tenant_id}/invite",
        json={"email": "newuser@example.com", "role": "member"},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 403
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "INSUFFICIENT_ROLE"


@pytest.mark.asyncio
async def test_duplicate_pending_invitation(client: AsyncClient, db_session):
    """AC-6.3: Duplicate Pending Invitation

    Given an active pending invitation exists for the email
    When I attempt to invite the same email again
    Then the request fails with 409 Conflict
    And error code is INVITE_ALREADY_EXISTS
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

    # Login as owner
    login_response = await client.post(
        "/auth/login",
        json={"email": "owner@acme.com", "password": "SecurePass123!"},
    )
    assert login_response.status_code == 200
    access_token = login_response.json()["access_token"]

    # First invitation (should succeed)
    response = await client.post(
        f"/tenants/{tenant_id}/invite",
        json={"email": "newuser@example.com", "role": "member"},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == 201

    # Second invitation to same email (should fail)
    response = await client.post(
        f"/tenants/{tenant_id}/invite",
        json={"email": "newuser@example.com", "role": "admin"},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 409
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "INVITE_ALREADY_EXISTS"


@pytest.mark.asyncio
async def test_user_already_member(client: AsyncClient, db_session):
    """AC-6.4: User Already a Member

    Given a user with the email is already a member
    When I attempt to invite them
    Then the request fails with 409 Conflict
    And error code is ALREADY_MEMBER
    """
    # Create first tenant with owner
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

    # Create a second user who will become a member
    signup_response2 = await client.post(
        "/auth/signup",
        json={
            "email": "member@acme.com",
            "password": "SecurePass123!",
            "tenant_name": "Member Corp",
        },
    )
    assert signup_response2.status_code == 201

    # Add second user to first tenant
    from src.domain.entities import Membership, MembershipRole, MembershipStatus, User
    from sqlmodel import select

    stmt = select(User).where(User.email == "member@acme.com")
    result = await db_session.exec(stmt)
    existing_member = result.one()

    membership = Membership(
        user_id=existing_member.id,
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

    # Try to invite the existing member
    response = await client.post(
        f"/tenants/{tenant_id}/invite",
        json={"email": "member@acme.com", "role": "admin"},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 409
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "ALREADY_MEMBER"


@pytest.mark.asyncio
async def test_invalid_role(client: AsyncClient):
    """AC-6.5: Invalid Role

    Given I specify an invalid role (e.g., "superadmin")
    When I attempt to invite
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

    # Login as owner
    login_response = await client.post(
        "/auth/login",
        json={"email": "owner@acme.com", "password": "SecurePass123!"},
    )
    assert login_response.status_code == 200
    access_token = login_response.json()["access_token"]

    # Try to invite with invalid role
    response = await client.post(
        f"/tenants/{tenant_id}/invite",
        json={"email": "newuser@example.com", "role": "superadmin"},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 400
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "INVALID_ROLE"


@pytest.mark.asyncio
async def test_admin_can_invite(client: AsyncClient, db_session):
    """Verify that admins (not just owners) can invite users

    This extends AC-6.1 to verify admins have permission.
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

    # Add admin to first tenant as "admin" role
    from src.domain.entities import Membership, MembershipRole, MembershipStatus, User
    from sqlmodel import select

    stmt = select(User).where(User.email == "admin@acme.com")
    result = await db_session.exec(stmt)
    admin_user = result.one()

    membership = Membership(
        user_id=admin_user.id,
        tenant_id=UUID(tenant_id),
        role=MembershipRole.admin,
        status=MembershipStatus.active,
    )
    db_session.add(membership)
    await db_session.commit()

    # Login as admin
    login_response = await client.post(
        "/auth/login",
        json={"email": "admin@acme.com", "password": "SecurePass123!"},
    )
    assert login_response.status_code == 200
    access_token = login_response.json()["access_token"]

    # Invite a user as admin (should succeed)
    response = await client.post(
        f"/tenants/{tenant_id}/invite",
        json={"email": "newuser@example.com", "role": "member"},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "pending"


@pytest.mark.asyncio
async def test_invite_unauthorized(client: AsyncClient):
    """Verify that unauthorized requests are rejected

    Given I don't provide a JWT token
    When I attempt to invite a user
    Then the request fails with 401 Unauthorized
    """
    response = await client.post(
        "/tenants/some-uuid/invite",
        json={"email": "newuser@example.com", "role": "member"},
    )

    assert response.status_code == 401
