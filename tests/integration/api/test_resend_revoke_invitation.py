import pytest
from httpx import AsyncClient
from uuid import UUID
from datetime import UTC, datetime, timedelta


@pytest.mark.asyncio
async def test_successful_resend_invitation(client: AsyncClient, db_session):
    """AC-15.1: Resend Invitation

    Given a pending invitation exists
    When I choose to resend
    Then a new invitation email is sent with the same token
    And the expiry is extended by 7 days from now
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

    # Create invitation
    invite_response = await client.post(
        f"/tenants/{tenant_id}/invite",
        json={"email": "newuser@example.com", "role": "member"},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert invite_response.status_code == 201
    invitation_id = invite_response.json()["invite_id"]

    # Resend invitation
    resend_response = await client.post(
        f"/invitations/{invitation_id}/resend",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert resend_response.status_code == 200
    data = resend_response.json()

    # Verify response structure
    assert data["status"] == "resent"
    assert "expires_at" in data

    # Verify invitation in database
    from src.domain.entities import Invitation
    from sqlmodel import select

    stmt = select(Invitation).where(Invitation.id == UUID(invitation_id))
    result = await db_session.exec(stmt)
    invitation = result.one()

    # Verify expiration was extended to ~7 days from now
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

    stmt = select(AuditEvent).where(AuditEvent.action == "invitation_resent")
    result = await db_session.exec(stmt)
    audit_events = result.all()
    assert len(audit_events) == 1
    assert audit_events[0].event_metadata["invitation_id"] == invitation_id


@pytest.mark.asyncio
async def test_resend_invitation_already_accepted(client: AsyncClient, db_session):
    """AC-15.3: Already Accepted

    Given the invitation was already accepted
    When I attempt to resend or revoke
    Then the request fails with 409 Conflict
    And error code is INVITATION_ALREADY_ACCEPTED
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

    # Create invitation
    invite_response = await client.post(
        f"/tenants/{tenant_id}/invite",
        json={"email": "newuser@example.com", "role": "member"},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert invite_response.status_code == 201
    invitation_id = invite_response.json()["invite_id"]

    # Manually mark invitation as accepted in DB (simulating acceptance)
    from src.domain.entities import Invitation, InvitationStatus
    from sqlmodel import select

    stmt = select(Invitation).where(Invitation.id == UUID(invitation_id))
    result = await db_session.exec(stmt)
    invitation = result.one()
    invitation.status = InvitationStatus.accepted
    db_session.add(invitation)
    await db_session.commit()

    # Try to resend accepted invitation
    resend_response = await client.post(
        f"/invitations/{invitation_id}/resend",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert resend_response.status_code == 409
    error = resend_response.json()["error"]
    assert error["code"] == "INVITATION_ALREADY_ACCEPTED"


@pytest.mark.asyncio
async def test_resend_invitation_insufficient_role(client: AsyncClient, db_session):
    """Test resend fails when user is not admin/owner"""
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

    # Create invitation as owner
    invite_response = await client.post(
        f"/tenants/{tenant_id}/invite",
        json={"email": "member@example.com", "role": "member"},
        headers={"Authorization": f"Bearer {owner_access_token}"},
    )
    assert invite_response.status_code == 201
    invitation_id = invite_response.json()["invite_id"]

    # Accept invitation and login as member
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

    # Create another invitation as owner
    invite_response2 = await client.post(
        f"/tenants/{tenant_id}/invite",
        json={"email": "another@example.com", "role": "member"},
        headers={"Authorization": f"Bearer {owner_access_token}"},
    )
    assert invite_response2.status_code == 201
    invitation_id2 = invite_response2.json()["invite_id"]

    # Try to resend as member (should fail)
    resend_response = await client.post(
        f"/invitations/{invitation_id2}/resend",
        headers={"Authorization": f"Bearer {member_access_token}"},
    )

    assert resend_response.status_code == 403
    error = resend_response.json()["error"]
    assert error["code"] == "INSUFFICIENT_ROLE"


@pytest.mark.asyncio
async def test_resend_invitation_not_found(client: AsyncClient, db_session):
    """Test resend fails when invitation doesn't exist"""
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
    access_token = signup_response.json()["access_token"]

    # Try to resend non-existent invitation
    from uuid import uuid4
    fake_id = str(uuid4())

    resend_response = await client.post(
        f"/invitations/{fake_id}/resend",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert resend_response.status_code == 404
    error = resend_response.json()["error"]
    assert error["code"] == "INVITATION_NOT_FOUND"


# ============================================================================
# Revoke Invitation Tests
# ============================================================================


@pytest.mark.asyncio
async def test_successful_revoke_invitation(client: AsyncClient, db_session):
    """AC-15.2: Revoke Invitation

    Given a pending invitation exists
    When I choose to revoke
    Then the Invitation.status is updated to expired
    And the user can no longer accept the invitation
    And an AuditEvent with action=invitation_revoked is recorded
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

    # Create invitation
    invite_response = await client.post(
        f"/tenants/{tenant_id}/invite",
        json={"email": "newuser@example.com", "role": "member"},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert invite_response.status_code == 201
    invitation_id = invite_response.json()["invite_id"]

    # Revoke invitation
    revoke_response = await client.delete(
        f"/invitations/{invitation_id}",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert revoke_response.status_code == 200
    data = revoke_response.json()
    assert data["status"] == "revoked"

    # Verify invitation status in database
    from src.domain.entities import Invitation, InvitationStatus
    from sqlmodel import select

    stmt = select(Invitation).where(Invitation.id == UUID(invitation_id))
    result = await db_session.exec(stmt)
    invitation = result.one()
    assert invitation.status == InvitationStatus.expired

    # Verify audit event was created (AC-15.2)
    from src.domain.entities import AuditEvent

    stmt = select(AuditEvent).where(AuditEvent.action == "invitation_revoked")
    result = await db_session.exec(stmt)
    audit_events = result.all()
    assert len(audit_events) == 1
    assert audit_events[0].event_metadata["invitation_id"] == invitation_id


@pytest.mark.asyncio
async def test_revoke_invitation_already_accepted(client: AsyncClient, db_session):
    """AC-15.3: Already Accepted

    Given the invitation was already accepted
    When I attempt to revoke
    Then the request fails with 409 Conflict
    And error code is INVITATION_ALREADY_ACCEPTED
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

    # Create invitation
    invite_response = await client.post(
        f"/tenants/{tenant_id}/invite",
        json={"email": "newuser@example.com", "role": "member"},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert invite_response.status_code == 201
    invitation_id = invite_response.json()["invite_id"]

    # Manually mark invitation as accepted in DB
    from src.domain.entities import Invitation, InvitationStatus
    from sqlmodel import select

    stmt = select(Invitation).where(Invitation.id == UUID(invitation_id))
    result = await db_session.exec(stmt)
    invitation = result.one()
    invitation.status = InvitationStatus.accepted
    db_session.add(invitation)
    await db_session.commit()

    # Try to revoke accepted invitation
    revoke_response = await client.delete(
        f"/invitations/{invitation_id}",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert revoke_response.status_code == 409
    error = revoke_response.json()["error"]
    assert error["code"] == "INVITATION_ALREADY_ACCEPTED"


@pytest.mark.asyncio
async def test_revoke_invitation_insufficient_role(client: AsyncClient, db_session):
    """Test revoke fails when user is not admin/owner"""
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

    # Create invitation as owner
    invite_response = await client.post(
        f"/tenants/{tenant_id}/invite",
        json={"email": "member@example.com", "role": "member"},
        headers={"Authorization": f"Bearer {owner_access_token}"},
    )
    assert invite_response.status_code == 201
    invitation_id = invite_response.json()["invite_id"]

    # Accept invitation and login as member
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

    # Create another invitation as owner
    invite_response2 = await client.post(
        f"/tenants/{tenant_id}/invite",
        json={"email": "another@example.com", "role": "member"},
        headers={"Authorization": f"Bearer {owner_access_token}"},
    )
    assert invite_response2.status_code == 201
    invitation_id2 = invite_response2.json()["invite_id"]

    # Try to revoke as member (should fail)
    revoke_response = await client.delete(
        f"/invitations/{invitation_id2}",
        headers={"Authorization": f"Bearer {member_access_token}"},
    )

    assert revoke_response.status_code == 403
    error = revoke_response.json()["error"]
    assert error["code"] == "INSUFFICIENT_ROLE"


@pytest.mark.asyncio
async def test_revoke_invitation_not_found(client: AsyncClient, db_session):
    """Test revoke fails when invitation doesn't exist"""
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
    access_token = signup_response.json()["access_token"]

    # Try to revoke non-existent invitation
    from uuid import uuid4
    fake_id = str(uuid4())

    revoke_response = await client.delete(
        f"/invitations/{fake_id}",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert revoke_response.status_code == 404
    error = revoke_response.json()["error"]
    assert error["code"] == "INVITATION_NOT_FOUND"
