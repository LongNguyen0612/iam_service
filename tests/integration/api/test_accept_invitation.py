import pytest
from httpx import AsyncClient
from uuid import UUID
from datetime import datetime, timedelta
import bcrypt


@pytest.mark.asyncio
async def test_existing_user_accepts_invitation(client: AsyncClient, db_session):
    """AC-14.1: Existing User Accepts Invite

    Given I am an existing user and received an invitation
    When I click the invitation link and confirm
    Then a Membership is created for me in the target tenant
    And the Invitation.status is updated to accepted
    And I receive a JWT scoped to the new tenant
    And an AuditEvent with action=invitation_accepted is recorded
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

    # Login as owner
    login_response = await client.post(
        "/auth/login",
        json={"email": "owner@acme.com", "password": "SecurePass123!"},
    )
    assert login_response.status_code == 200
    owner_token = login_response.json()["access_token"]

    # Create existing user in their own tenant
    existing_user_signup = await client.post(
        "/auth/signup",
        json={
            "email": "existing@example.com",
            "password": "ExistingPass123!",
            "tenant_name": "Existing Corp",
        },
    )
    assert existing_user_signup.status_code == 201

    # Owner invites existing user to Acme Corp
    invite_response = await client.post(
        f"/tenants/{tenant_id}/invite",
        json={"email": "existing@example.com", "role": "member"},
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert invite_response.status_code == 201
    invite_id = invite_response.json()["invite_id"]

    # Get invitation token from database
    from src.domain.entities import Invitation
    from sqlmodel import select

    stmt = select(Invitation).where(Invitation.id == UUID(invite_id))
    result = await db_session.exec(stmt)
    invitation = result.one()
    invitation_token = invitation.token

    # Accept invitation (no password needed for existing user)
    response = await client.post(
        "/invitations/accept",
        json={"token": invitation_token},
    )

    assert response.status_code == 200
    data = response.json()

    # Verify response structure
    assert "access_token" in data
    assert "refresh_token" in data
    assert "tenant" in data
    assert "email_verification_required" in data

    # Verify tenant information
    assert data["tenant"]["id"] == tenant_id
    assert data["tenant"]["name"] == "Acme Corp"
    assert data["tenant"]["role"] == "member"

    # Existing user still needs email verification if they haven't verified
    # (users created via signup start with email_verified=False)
    assert data["email_verification_required"] is True

    # Get the user that accepted the invitation
    from src.domain.entities import User, Membership
    from sqlmodel import select

    stmt = select(User).where(User.email == invitation.email)
    result = await db_session.exec(stmt)
    user = result.one()

    # Verify membership was created
    stmt = select(Membership).where(
        Membership.tenant_id == UUID(tenant_id),
        Membership.user_id == user.id,
    )
    result = await db_session.exec(stmt)
    membership = result.one()
    assert membership.role.value == "member"
    assert membership.status.value == "active"

    # Verify invitation status updated
    await db_session.refresh(invitation)
    assert invitation.status.value == "accepted"

    # Verify audit event created
    from src.domain.entities import AuditEvent

    stmt = (
        select(AuditEvent)
        .where(AuditEvent.action == "invitation_accepted")
        .where(AuditEvent.tenant_id == UUID(tenant_id))
    )
    result = await db_session.exec(stmt)
    audit_events = result.all()
    assert len(audit_events) > 0
    audit = audit_events[-1]
    assert audit.event_metadata["invitation_id"] == str(invitation.id)
    assert audit.event_metadata["is_new_user"] is False

    # Verify session created
    from src.domain.entities import Session

    stmt = (
        select(Session)
        .where(Session.user_id == user.id)
        .where(Session.tenant_id == UUID(tenant_id))
    )
    result = await db_session.exec(stmt)
    sessions = result.all()
    assert len(sessions) > 0


@pytest.mark.asyncio
async def test_new_user_accepts_invitation(client: AsyncClient, db_session):
    """AC-14.2: New User Accepts Invite

    Given I do not have an account and received an invitation
    When I click the link and provide a password
    Then a User account is created with the invited email
    And a Membership is created in the target tenant
    And the Invitation.status is updated to accepted
    And I receive a JWT scoped to the new tenant
    And email verification is required
    """
    # Create tenant with owner
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
    owner_token = login_response.json()["access_token"]

    # Owner invites new user
    invite_response = await client.post(
        f"/tenants/{tenant_id}/invite",
        json={"email": "newuser@example.com", "role": "admin"},
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert invite_response.status_code == 201
    invite_id = invite_response.json()["invite_id"]

    # Get invitation token
    from src.domain.entities import Invitation
    from sqlmodel import select

    stmt = select(Invitation).where(Invitation.id == UUID(invite_id))
    result = await db_session.exec(stmt)
    invitation = result.one()
    invitation_token = invitation.token

    # New user accepts invitation with password
    response = await client.post(
        "/invitations/accept",
        json={"token": invitation_token, "password": "NewUserPass123!"},
    )

    assert response.status_code == 200
    data = response.json()

    # Verify response
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["tenant"]["id"] == tenant_id
    assert data["tenant"]["name"] == "Acme Corp"
    assert data["tenant"]["role"] == "admin"

    # New user should require email verification
    assert data["email_verification_required"] is True

    # Verify user was created
    from src.domain.entities import User

    stmt = select(User).where(User.email == "newuser@example.com")
    result = await db_session.exec(stmt)
    user = result.one()
    assert user.email == "newuser@example.com"
    assert user.email_verified is False
    assert bcrypt.checkpw(b"NewUserPass123!", user.password_hash.encode("utf-8"))

    # Verify membership was created
    from src.domain.entities import Membership

    stmt = (
        select(Membership)
        .where(Membership.user_id == user.id)
        .where(Membership.tenant_id == UUID(tenant_id))
    )
    result = await db_session.exec(stmt)
    membership = result.one()
    assert membership.role.value == "admin"

    # Verify invitation status
    await db_session.refresh(invitation)
    assert invitation.status.value == "accepted"

    # Verify audit event
    from src.domain.entities import AuditEvent

    stmt = (
        select(AuditEvent)
        .where(AuditEvent.action == "invitation_accepted")
        .where(AuditEvent.user_id == user.id)
    )
    result = await db_session.exec(stmt)
    audit = result.one()
    assert audit.event_metadata["is_new_user"] is True


@pytest.mark.asyncio
async def test_expired_invitation(client: AsyncClient, db_session):
    """AC-14.3: Expired Invitation

    Given the invitation has expired
    When I attempt to accept
    Then the request fails with 410 Gone
    And error code is INVITATION_EXPIRED
    """
    # Create tenant
    signup_response = await client.post(
        "/auth/signup",
        json={
            "email": "owner@acme.com",
            "password": "SecurePass123!",
            "tenant_name": "Acme Corp",
        },
    )
    tenant_id = signup_response.json()["tenant"]["id"]

    # Create expired invitation manually
    from src.domain.entities import Invitation, InvitationStatus, MembershipRole

    invitation = Invitation(
        tenant_id=UUID(tenant_id),
        email="expired@example.com",
        role=MembershipRole.member,
        status=InvitationStatus.pending,
        expires_at=datetime.utcnow() - timedelta(hours=1),  # Expired 1 hour ago
        token="expired_token_12345",
    )
    db_session.add(invitation)
    await db_session.commit()

    # Attempt to accept expired invitation
    response = await client.post(
        "/invitations/accept",
        json={"token": "expired_token_12345"},
    )

    assert response.status_code == 410  # Gone
    error = response.json()["error"]
    assert error["code"] == "INVITATION_EXPIRED"

    # Verify invitation status was updated to expired
    await db_session.refresh(invitation)
    assert invitation.status == InvitationStatus.expired


@pytest.mark.asyncio
async def test_already_accepted_invitation(client: AsyncClient, db_session):
    """AC-14.4: Already Accepted Invitation

    Given the invitation was already accepted
    When I attempt to accept again
    Then the request fails with 409 Conflict
    And error code is INVITATION_ALREADY_ACCEPTED
    """
    # Create tenant
    signup_response = await client.post(
        "/auth/signup",
        json={
            "email": "owner@acme.com",
            "password": "SecurePass123!",
            "tenant_name": "Acme Corp",
        },
    )
    tenant_id = signup_response.json()["tenant"]["id"]

    # Create already accepted invitation
    from src.domain.entities import Invitation, InvitationStatus, MembershipRole

    invitation = Invitation(
        tenant_id=UUID(tenant_id),
        email="already@example.com",
        role=MembershipRole.member,
        status=InvitationStatus.accepted,  # Already accepted
        expires_at=datetime.utcnow() + timedelta(days=7),
        token="already_accepted_token",
    )
    db_session.add(invitation)
    await db_session.commit()

    # Attempt to accept again
    response = await client.post(
        "/invitations/accept",
        json={"token": "already_accepted_token"},
    )

    assert response.status_code == 409  # Conflict
    error = response.json()["error"]
    assert error["code"] == "INVITATION_ALREADY_ACCEPTED"


@pytest.mark.asyncio
async def test_invalid_token(client: AsyncClient, db_session):
    """Test invalid or non-existent invitation token

    When I attempt to accept with invalid token
    Then the request fails with 400 Bad Request
    And error code is INVALID_TOKEN
    """
    response = await client.post(
        "/invitations/accept",
        json={"token": "non_existent_token"},
    )

    assert response.status_code == 400
    error = response.json()["error"]
    assert error["code"] == "INVALID_TOKEN"


@pytest.mark.asyncio
async def test_new_user_missing_password(client: AsyncClient, db_session):
    """Test that new users must provide a password

    Given I am a new user
    When I attempt to accept without a password
    Then the request fails with 400 Bad Request
    And error code is PASSWORD_REQUIRED
    """
    # Create tenant
    signup_response = await client.post(
        "/auth/signup",
        json={
            "email": "owner@acme.com",
            "password": "SecurePass123!",
            "tenant_name": "Acme Corp",
        },
    )
    tenant_id = signup_response.json()["tenant"]["id"]

    login_response = await client.post(
        "/auth/login",
        json={"email": "owner@acme.com", "password": "SecurePass123!"},
    )
    owner_token = login_response.json()["access_token"]

    # Invite new user
    invite_response = await client.post(
        f"/tenants/{tenant_id}/invite",
        json={"email": "newuser@example.com", "role": "member"},
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    invite_id = invite_response.json()["invite_id"]

    # Get invitation token
    from src.domain.entities import Invitation
    from sqlmodel import select

    stmt = select(Invitation).where(Invitation.id == UUID(invite_id))
    result = await db_session.exec(stmt)
    invitation = result.one()

    # Attempt to accept without password
    response = await client.post(
        "/invitations/accept",
        json={"token": invitation.token},  # No password
    )

    assert response.status_code == 400
    error = response.json()["error"]
    assert error["code"] == "PASSWORD_REQUIRED"


@pytest.mark.asyncio
async def test_password_too_short(client: AsyncClient, db_session):
    """Test that password must be at least 8 characters

    When I provide a password shorter than 8 characters
    Then the request fails with 400 Bad Request
    And error code is INVALID_PASSWORD
    """
    # Create tenant
    signup_response = await client.post(
        "/auth/signup",
        json={
            "email": "owner@acme.com",
            "password": "SecurePass123!",
            "tenant_name": "Acme Corp",
        },
    )
    tenant_id = signup_response.json()["tenant"]["id"]

    login_response = await client.post(
        "/auth/login",
        json={"email": "owner@acme.com", "password": "SecurePass123!"},
    )
    owner_token = login_response.json()["access_token"]

    # Invite new user
    invite_response = await client.post(
        f"/tenants/{tenant_id}/invite",
        json={"email": "newuser@example.com", "role": "member"},
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    invite_id = invite_response.json()["invite_id"]

    # Get invitation token
    from src.domain.entities import Invitation
    from sqlmodel import select

    stmt = select(Invitation).where(Invitation.id == UUID(invite_id))
    result = await db_session.exec(stmt)
    invitation = result.one()

    # Attempt with short password
    response = await client.post(
        "/invitations/accept",
        json={"token": invitation.token, "password": "short"},  # Only 5 chars
    )

    assert response.status_code == 400
    error = response.json()["error"]
    assert error["code"] == "INVALID_PASSWORD"


@pytest.mark.asyncio
async def test_user_already_active_member(client: AsyncClient, db_session):
    """Test that user cannot accept invitation if already an active member

    Given I am already an active member of the tenant
    When I attempt to accept an invitation
    Then the request fails with 409 Conflict
    And error code is ALREADY_MEMBER
    """
    # Create tenant with owner
    signup_response = await client.post(
        "/auth/signup",
        json={
            "email": "user@acme.com",
            "password": "SecurePass123!",
            "tenant_name": "Acme Corp",
        },
    )
    tenant_id = signup_response.json()["tenant"]["id"]

    # User creates their own tenant and is owner
    # Now create an invitation for them to the same tenant (manually)
    from src.domain.entities import Invitation, InvitationStatus, MembershipRole, User
    from sqlmodel import select

    stmt = select(User).where(User.email == "user@acme.com")
    result = await db_session.exec(stmt)
    user = result.one()

    invitation = Invitation(
        tenant_id=UUID(tenant_id),
        email="user@acme.com",
        role=MembershipRole.member,
        status=InvitationStatus.pending,
        expires_at=datetime.utcnow() + timedelta(days=7),
        token="already_member_token",
    )
    db_session.add(invitation)
    await db_session.commit()

    # Attempt to accept
    response = await client.post(
        "/invitations/accept",
        json={"token": "already_member_token"},
    )

    assert response.status_code == 409
    error = response.json()["error"]
    assert error["code"] == "ALREADY_MEMBER"


@pytest.mark.asyncio
async def test_can_login_with_new_credentials(client: AsyncClient, db_session):
    """Test that new user can login after accepting invitation

    Given I accepted an invitation as a new user
    When I login with my email and password
    Then I should be able to authenticate successfully
    """
    # Create tenant with owner
    signup_response = await client.post(
        "/auth/signup",
        json={
            "email": "owner@acme.com",
            "password": "SecurePass123!",
            "tenant_name": "Acme Corp",
        },
    )
    tenant_id = signup_response.json()["tenant"]["id"]

    login_response = await client.post(
        "/auth/login",
        json={"email": "owner@acme.com", "password": "SecurePass123!"},
    )
    owner_token = login_response.json()["access_token"]

    # Invite new user
    invite_response = await client.post(
        f"/tenants/{tenant_id}/invite",
        json={"email": "newuser@example.com", "role": "member"},
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    invite_id = invite_response.json()["invite_id"]

    # Get invitation token
    from src.domain.entities import Invitation
    from sqlmodel import select

    stmt = select(Invitation).where(Invitation.id == UUID(invite_id))
    result = await db_session.exec(stmt)
    invitation = result.one()

    # Accept invitation
    accept_response = await client.post(
        "/invitations/accept",
        json={"token": invitation.token, "password": "NewUserPass123!"},
    )
    assert accept_response.status_code == 200

    # Try to login with new credentials
    login_response = await client.post(
        "/auth/login",
        json={"email": "newuser@example.com", "password": "NewUserPass123!"},
    )

    assert login_response.status_code == 200
    data = login_response.json()
    assert "access_token" in data
    assert "refresh_token" in data


@pytest.mark.asyncio
async def test_existing_user_can_access_multiple_tenants(
    client: AsyncClient, db_session
):
    """Test that user can be member of multiple tenants after accepting invitation

    Given I have my own tenant
    When I accept an invitation to another tenant
    Then I should be able to switch between tenants
    """
    # User creates their own tenant
    signup_response = await client.post(
        "/auth/signup",
        json={
            "email": "user@example.com",
            "password": "UserPass123!",
            "tenant_name": "User Corp",
        },
    )
    assert signup_response.status_code == 201
    own_tenant_id = signup_response.json()["tenant"]["id"]

    # Another person creates a tenant
    other_signup = await client.post(
        "/auth/signup",
        json={
            "email": "owner@acme.com",
            "password": "OwnerPass123!",
            "tenant_name": "Acme Corp",
        },
    )
    acme_tenant_id = other_signup.json()["tenant"]["id"]

    # Owner logs in and invites the user
    login_response = await client.post(
        "/auth/login",
        json={"email": "owner@acme.com", "password": "OwnerPass123!"},
    )
    owner_token = login_response.json()["access_token"]

    invite_response = await client.post(
        f"/tenants/{acme_tenant_id}/invite",
        json={"email": "user@example.com", "role": "member"},
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    invite_id = invite_response.json()["invite_id"]

    # Get invitation token
    from src.domain.entities import Invitation
    from sqlmodel import select

    stmt = select(Invitation).where(Invitation.id == UUID(invite_id))
    result = await db_session.exec(stmt)
    invitation = result.one()

    # User accepts invitation (no password needed, existing user)
    accept_response = await client.post(
        "/invitations/accept",
        json={"token": invitation.token},
    )
    assert accept_response.status_code == 200

    # Verify user now has access to Acme Corp
    data = accept_response.json()
    assert data["tenant"]["id"] == acme_tenant_id
    assert data["tenant"]["name"] == "Acme Corp"

    # User should be able to login
    user_login = await client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "UserPass123!"},
    )
    assert user_login.status_code == 200
