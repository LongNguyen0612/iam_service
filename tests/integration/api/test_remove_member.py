import pytest
from httpx import AsyncClient
from uuid import UUID


@pytest.mark.asyncio
async def test_successful_member_removal_by_owner(client: AsyncClient, db_session):
    """AC-16.1: Successful Member Removal

    Given I am an owner or admin
    When I remove a member
    Then the Membership.status is updated to revoked
    And all active Sessions for that user in this tenant are revoked
    And an AuditEvent with action=member_removed is recorded
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
    owner_access_token = signup_response.json()["access_token"]

    # Invite a member
    invite_response = await client.post(
        f"/tenants/{tenant_id}/invite",
        json={"email": "member@example.com", "role": "member"},
        headers={"Authorization": f"Bearer {owner_access_token}"},
    )
    assert invite_response.status_code == 201
    invitation_id = invite_response.json()["invite_id"]

    # Accept invitation
    from src.domain.entities import Invitation
    from sqlmodel import select

    stmt = select(Invitation).where(Invitation.id == UUID(invitation_id))
    result = await db_session.exec(stmt)
    invitation = result.one()
    invitation_token = invitation.token

    accept_response = await client.post(
        "/invitations/accept",
        json={"token": invitation_token, "password": "MemberPass123!"},
    )
    assert accept_response.status_code == 200
    member_access_token = accept_response.json()["access_token"]

    # Get member user_id
    from src.domain.entities import User

    stmt = select(User).where(User.email == "member@example.com")
    result = await db_session.exec(stmt)
    member_user = result.one()
    member_user_id = str(member_user.id)

    # Remove member
    remove_response = await client.delete(
        f"/tenants/{tenant_id}/members/{member_user_id}",
        headers={"Authorization": f"Bearer {owner_access_token}"},
    )

    assert remove_response.status_code == 200
    data = remove_response.json()
    assert data["status"] == "removed"

    # Verify membership was revoked (AC-16.1)
    from src.domain.entities import Membership, MembershipStatus

    stmt = select(Membership).where(
        Membership.user_id == UUID(member_user_id),
        Membership.tenant_id == UUID(tenant_id),
    )
    result = await db_session.exec(stmt)
    membership = result.one()
    assert membership.status == MembershipStatus.revoked

    # Verify sessions were revoked (AC-16.1)
    from src.domain.entities import Session

    stmt = select(Session).where(
        Session.user_id == UUID(member_user_id), Session.tenant_id == UUID(tenant_id)
    )
    result = await db_session.exec(stmt)
    sessions = result.all()
    for session in sessions:
        assert session.revoked is True

    # Verify audit event was created (AC-16.1)
    from src.domain.entities import AuditEvent

    stmt = select(AuditEvent).where(AuditEvent.action == "member_removed")
    result = await db_session.exec(stmt)
    audit_events = result.all()
    assert len(audit_events) == 1
    assert audit_events[0].event_metadata["removed_user_id"] == member_user_id


@pytest.mark.asyncio
async def test_successful_member_removal_by_admin(client: AsyncClient, db_session):
    """Test admin can remove members"""
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
    owner_access_token = signup_response.json()["access_token"]

    # Invite admin
    invite_response1 = await client.post(
        f"/tenants/{tenant_id}/invite",
        json={"email": "admin@example.com", "role": "admin"},
        headers={"Authorization": f"Bearer {owner_access_token}"},
    )
    assert invite_response1.status_code == 201

    # Accept admin invitation
    from src.domain.entities import Invitation
    from sqlmodel import select

    stmt = select(Invitation).where(Invitation.email == "admin@example.com")
    result = await db_session.exec(stmt)
    admin_invitation = result.one()

    accept_response = await client.post(
        "/invitations/accept",
        json={"token": admin_invitation.token, "password": "AdminPass123!"},
    )
    assert accept_response.status_code == 200
    admin_access_token = accept_response.json()["access_token"]

    # Invite a member
    invite_response2 = await client.post(
        f"/tenants/{tenant_id}/invite",
        json={"email": "member@example.com", "role": "member"},
        headers={"Authorization": f"Bearer {owner_access_token}"},
    )
    assert invite_response2.status_code == 201

    # Accept member invitation
    stmt = select(Invitation).where(Invitation.email == "member@example.com")
    result = await db_session.exec(stmt)
    member_invitation = result.one()

    accept_response2 = await client.post(
        "/invitations/accept",
        json={"token": member_invitation.token, "password": "MemberPass123!"},
    )
    assert accept_response2.status_code == 200

    # Get member user_id
    from src.domain.entities import User

    stmt = select(User).where(User.email == "member@example.com")
    result = await db_session.exec(stmt)
    member_user = result.one()
    member_user_id = str(member_user.id)

    # Admin removes member
    remove_response = await client.delete(
        f"/tenants/{tenant_id}/members/{member_user_id}",
        headers={"Authorization": f"Bearer {admin_access_token}"},
    )

    assert remove_response.status_code == 200
    assert remove_response.json()["status"] == "removed"


@pytest.mark.asyncio
async def test_owner_removes_self_with_multiple_owners(client: AsyncClient, db_session):
    """AC-16.3: Owner Removes Self (Multiple Owners)

    Given there are multiple owners
    When I remove myself
    Then the removal succeeds
    And I lose access to the tenant
    """
    # Create tenant owner 1
    signup_response = await client.post(
        "/auth/signup",
        json={
            "email": "owner1@acme.com",
            "password": "SecurePass123!",
            "tenant_name": "Acme Corp",
        },
    )
    assert signup_response.status_code == 201
    tenant_id = signup_response.json()["tenant"]["id"]
    owner1_access_token = signup_response.json()["access_token"]

    # Invite owner 2
    invite_response = await client.post(
        f"/tenants/{tenant_id}/invite",
        json={"email": "owner2@example.com", "role": "owner"},
        headers={"Authorization": f"Bearer {owner1_access_token}"},
    )
    assert invite_response.status_code == 201

    # Accept owner 2 invitation
    from src.domain.entities import Invitation
    from sqlmodel import select

    stmt = select(Invitation).where(Invitation.email == "owner2@example.com")
    result = await db_session.exec(stmt)
    owner2_invitation = result.one()

    accept_response = await client.post(
        "/invitations/accept",
        json={"token": owner2_invitation.token, "password": "Owner2Pass123!"},
    )
    assert accept_response.status_code == 200

    # Get owner1 user_id
    from src.domain.entities import User

    stmt = select(User).where(User.email == "owner1@acme.com")
    result = await db_session.exec(stmt)
    owner1_user = result.one()
    owner1_user_id = str(owner1_user.id)

    # Owner1 removes themselves (AC-16.3)
    remove_response = await client.delete(
        f"/tenants/{tenant_id}/members/{owner1_user_id}",
        headers={"Authorization": f"Bearer {owner1_access_token}"},
    )

    assert remove_response.status_code == 200
    assert remove_response.json()["status"] == "removed"

    # Verify membership was revoked
    from src.domain.entities import Membership, MembershipStatus
    from uuid import UUID

    stmt = select(Membership).where(
        Membership.user_id == UUID(owner1_user_id),
        Membership.tenant_id == UUID(tenant_id),
    )
    result = await db_session.exec(stmt)
    membership = result.one()
    assert membership.status == MembershipStatus.revoked


@pytest.mark.asyncio
async def test_cannot_remove_last_owner(client: AsyncClient, db_session):
    """AC-16.2: Owner Removes Self (Last Owner)

    Given I am the only owner
    When I attempt to remove myself
    Then the request fails with 409 Conflict
    And error code is CANNOT_REMOVE_LAST_OWNER
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
    owner_access_token = signup_response.json()["access_token"]

    # Get owner user_id
    from src.domain.entities import User
    from sqlmodel import select

    stmt = select(User).where(User.email == "owner@acme.com")
    result = await db_session.exec(stmt)
    owner_user = result.one()
    owner_user_id = str(owner_user.id)

    # Try to remove last owner (AC-16.2)
    remove_response = await client.delete(
        f"/tenants/{tenant_id}/members/{owner_user_id}",
        headers={"Authorization": f"Bearer {owner_access_token}"},
    )

    assert remove_response.status_code == 409
    error = remove_response.json()["error"]
    assert error["code"] == "CANNOT_REMOVE_LAST_OWNER"


@pytest.mark.asyncio
async def test_admin_cannot_remove_owner(client: AsyncClient, db_session):
    """AC-16.4: Admin Removes Owner

    Given I am an admin (not owner)
    When I attempt to remove an owner
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
    owner_access_token = signup_response.json()["access_token"]

    # Invite admin
    invite_response = await client.post(
        f"/tenants/{tenant_id}/invite",
        json={"email": "admin@example.com", "role": "admin"},
        headers={"Authorization": f"Bearer {owner_access_token}"},
    )
    assert invite_response.status_code == 201

    # Accept admin invitation
    from src.domain.entities import Invitation
    from sqlmodel import select

    stmt = select(Invitation).where(Invitation.email == "admin@example.com")
    result = await db_session.exec(stmt)
    admin_invitation = result.one()

    accept_response = await client.post(
        "/invitations/accept",
        json={"token": admin_invitation.token, "password": "AdminPass123!"},
    )
    assert accept_response.status_code == 200
    admin_access_token = accept_response.json()["access_token"]

    # Get owner user_id
    from src.domain.entities import User

    stmt = select(User).where(User.email == "owner@acme.com")
    result = await db_session.exec(stmt)
    owner_user = result.one()
    owner_user_id = str(owner_user.id)

    # Admin tries to remove owner (AC-16.4)
    remove_response = await client.delete(
        f"/tenants/{tenant_id}/members/{owner_user_id}",
        headers={"Authorization": f"Bearer {admin_access_token}"},
    )

    assert remove_response.status_code == 403
    error = remove_response.json()["error"]
    assert error["code"] == "INSUFFICIENT_ROLE"


@pytest.mark.asyncio
async def test_member_cannot_remove_anyone(client: AsyncClient, db_session):
    """Test member cannot remove other members"""
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
    owner_access_token = signup_response.json()["access_token"]

    # Invite member1
    invite_response1 = await client.post(
        f"/tenants/{tenant_id}/invite",
        json={"email": "member1@example.com", "role": "member"},
        headers={"Authorization": f"Bearer {owner_access_token}"},
    )
    assert invite_response1.status_code == 201

    # Accept member1 invitation
    from src.domain.entities import Invitation
    from sqlmodel import select

    stmt = select(Invitation).where(Invitation.email == "member1@example.com")
    result = await db_session.exec(stmt)
    member1_invitation = result.one()

    accept_response1 = await client.post(
        "/invitations/accept",
        json={"token": member1_invitation.token, "password": "Member1Pass123!"},
    )
    assert accept_response1.status_code == 200
    member1_access_token = accept_response1.json()["access_token"]

    # Invite member2
    invite_response2 = await client.post(
        f"/tenants/{tenant_id}/invite",
        json={"email": "member2@example.com", "role": "member"},
        headers={"Authorization": f"Bearer {owner_access_token}"},
    )
    assert invite_response2.status_code == 201

    # Accept member2 invitation
    stmt = select(Invitation).where(Invitation.email == "member2@example.com")
    result = await db_session.exec(stmt)
    member2_invitation = result.one()

    accept_response2 = await client.post(
        "/invitations/accept",
        json={"token": member2_invitation.token, "password": "Member2Pass123!"},
    )
    assert accept_response2.status_code == 200

    # Get member2 user_id
    from src.domain.entities import User

    stmt = select(User).where(User.email == "member2@example.com")
    result = await db_session.exec(stmt)
    member2_user = result.one()
    member2_user_id = str(member2_user.id)

    # Member1 tries to remove member2 (should fail)
    remove_response = await client.delete(
        f"/tenants/{tenant_id}/members/{member2_user_id}",
        headers={"Authorization": f"Bearer {member1_access_token}"},
    )

    assert remove_response.status_code == 403
    error = remove_response.json()["error"]
    assert error["code"] == "INSUFFICIENT_ROLE"


@pytest.mark.asyncio
async def test_membership_not_found(client: AsyncClient, db_session):
    """Test removal fails when target user is not a member"""
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
    owner_access_token = signup_response.json()["access_token"]

    # Try to remove non-existent user
    from uuid import uuid4

    fake_user_id = str(uuid4())

    remove_response = await client.delete(
        f"/tenants/{tenant_id}/members/{fake_user_id}",
        headers={"Authorization": f"Bearer {owner_access_token}"},
    )

    assert remove_response.status_code == 404
    error = remove_response.json()["error"]
    assert error["code"] == "MEMBERSHIP_NOT_FOUND"
