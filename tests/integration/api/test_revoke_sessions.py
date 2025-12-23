"""
Integration tests for Session Revocation API - IAM-008
"""

import pytest
from httpx import AsyncClient
from datetime import datetime, timedelta
from uuid import uuid4

from src.domain.entities import User, Tenant, Membership, MembershipRole, Session
from src.api.utils.jwt import generate_jwt


@pytest.mark.asyncio
async def test_revoke_all_sessions_self(client: AsyncClient, db_session):
    """Test user revoking all their own sessions"""
    # Setup: Create user, tenant, membership, and sessions
    user = User(
        id=uuid4(),
        email="user@example.com",
        password_hash="hash",
    )
    db_session.add(user)

    tenant = Tenant(id=uuid4(), name="Test Tenant")
    db_session.add(tenant)

    membership = Membership(
        id=uuid4(),
        user_id=user.id,
        tenant_id=tenant.id,
        role=MembershipRole.member,
    )
    db_session.add(membership)

    # Create 3 sessions
    for i in range(3):
        session = Session(
            id=uuid4(),
            user_id=user.id,
            tenant_id=tenant.id,
            refresh_token_hash="hash",
            expires_at=datetime.utcnow() + timedelta(days=30),
            revoked=False,
        )
        db_session.add(session)

    await db_session.commit()

    # Generate JWT
    token = generate_jwt(user.id, tenant.id, MembershipRole.member.value)

    # Make request
    response = await client.post(
        "/sessions/revoke-all",
        json={"user_id": str(user.id)},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["revoked_count"] == 3
    assert "Successfully revoked 3 session(s)" in data["message"]


@pytest.mark.asyncio
async def test_revoke_all_sessions_admin(client: AsyncClient, db_session):
    """Test admin revoking another user's sessions"""
    # Setup: Create admin user, target user, tenant, memberships
    admin = User(id=uuid4(), email="admin@example.com", password_hash="hash")
    target_user = User(id=uuid4(), email="target@example.com", password_hash="hash")
    db_session.add(admin)
    db_session.add(target_user)

    tenant = Tenant(id=uuid4(), name="Test Tenant")
    db_session.add(tenant)

    admin_membership = Membership(
        id=uuid4(),
        user_id=admin.id,
        tenant_id=tenant.id,
        role=MembershipRole.admin,
    )
    target_membership = Membership(
        id=uuid4(),
        user_id=target_user.id,
        tenant_id=tenant.id,
        role=MembershipRole.member,
    )
    db_session.add(admin_membership)
    db_session.add(target_membership)

    # Create 2 sessions for target user
    for i in range(2):
        session = Session(
            id=uuid4(),
            user_id=target_user.id,
            tenant_id=tenant.id,
            refresh_token_hash="hash",
            expires_at=datetime.utcnow() + timedelta(days=30),
            revoked=False,
        )
        db_session.add(session)

    await db_session.commit()

    # Generate admin JWT
    token = generate_jwt(admin.id, tenant.id, MembershipRole.admin.value)

    # Make request
    response = await client.post(
        "/sessions/revoke-all",
        json={"user_id": str(target_user.id)},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["revoked_count"] == 2


@pytest.mark.asyncio
async def test_revoke_all_sessions_forbidden(client: AsyncClient, db_session):
    """Test non-admin cannot revoke other user's sessions"""
    # Setup users
    user = User(id=uuid4(), email="user@example.com", password_hash="hash")
    other_user = User(id=uuid4(), email="other@example.com", password_hash="hash")
    db_session.add(user)
    db_session.add(other_user)

    tenant = Tenant(id=uuid4(), name="Test Tenant")
    db_session.add(tenant)

    membership = Membership(
        id=uuid4(),
        user_id=user.id,
        tenant_id=tenant.id,
        role=MembershipRole.member,
    )
    db_session.add(membership)
    await db_session.commit()

    # Generate user JWT
    token = generate_jwt(user.id, tenant.id, MembershipRole.member.value)

    # Try to revoke other user's sessions
    response = await client.post(
        "/sessions/revoke-all",
        json={"user_id": str(other_user.id)},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403
    data = response.json()
    assert data["error"]["code"] == "FORBIDDEN"


@pytest.mark.asyncio
async def test_revoke_specific_session(client: AsyncClient, db_session):
    """Test revoking a specific session by ID"""
    # Setup
    user = User(id=uuid4(), email="user@example.com", password_hash="hash")
    db_session.add(user)

    tenant = Tenant(id=uuid4(), name="Test Tenant")
    db_session.add(tenant)

    membership = Membership(
        id=uuid4(),
        user_id=user.id,
        tenant_id=tenant.id,
        role=MembershipRole.member,
    )
    db_session.add(membership)

    session = Session(
        id=uuid4(),
        user_id=user.id,
        tenant_id=tenant.id,
        refresh_token_hash="hash",
        expires_at=datetime.utcnow() + timedelta(days=30),
        revoked=False,
    )
    db_session.add(session)
    await db_session.commit()

    # Generate JWT
    token = generate_jwt(user.id, tenant.id, MembershipRole.member.value)

    # Revoke specific session
    response = await client.delete(
        f"/sessions/{session.id}",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["session_id"] == str(session.id)
    assert data["revoked"] is True


@pytest.mark.asyncio
async def test_revoke_specific_session_not_found(client: AsyncClient, db_session):
    """Test error when session doesn't exist"""
    user = User(id=uuid4(), email="user@example.com", password_hash="hash")
    db_session.add(user)

    tenant = Tenant(id=uuid4(), name="Test Tenant")
    db_session.add(tenant)

    membership = Membership(
        id=uuid4(),
        user_id=user.id,
        tenant_id=tenant.id,
        role=MembershipRole.member,
    )
    db_session.add(membership)
    await db_session.commit()

    token = generate_jwt(user.id, tenant.id, MembershipRole.member.value)

    # Try to revoke non-existent session
    fake_session_id = uuid4()
    response = await client.delete(
        f"/sessions/{fake_session_id}",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 404
    data = response.json()
    assert data["error"]["code"] == "SESSION_NOT_FOUND"


@pytest.mark.asyncio
async def test_revoke_all_except_current(client: AsyncClient, db_session):
    """Test revoking all sessions except current one"""
    # Setup
    user = User(id=uuid4(), email="user@example.com", password_hash="hash")
    db_session.add(user)

    tenant = Tenant(id=uuid4(), name="Test Tenant")
    db_session.add(tenant)

    membership = Membership(
        id=uuid4(),
        user_id=user.id,
        tenant_id=tenant.id,
        role=MembershipRole.member,
    )
    db_session.add(membership)

    # Create current session
    current_session = Session(
        id=uuid4(),
        user_id=user.id,
        tenant_id=tenant.id,
        refresh_token_hash="hash",
        expires_at=datetime.utcnow() + timedelta(days=30),
        revoked=False,
    )
    db_session.add(current_session)

    # Create 3 other sessions
    for i in range(3):
        session = Session(
            id=uuid4(),
            user_id=user.id,
            tenant_id=tenant.id,
            refresh_token_hash="hash",
            expires_at=datetime.utcnow() + timedelta(days=30),
            revoked=False,
        )
        db_session.add(session)

    await db_session.commit()

    # Generate JWT
    token = generate_jwt(user.id, tenant.id, MembershipRole.member.value)

    # Revoke all except current
    response = await client.post(
        "/sessions/revoke-others",
        json={"current_session_id": str(current_session.id)},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["revoked_count"] == 3
    assert "Successfully revoked 3 other session(s)" in data["message"]


@pytest.mark.asyncio
async def test_revoke_sessions_unauthorized(client: AsyncClient, db_session):
    """Test that endpoints require authentication"""
    fake_user_id = uuid4()

    # Test revoke-all without token
    response = await client.post(
        "/sessions/revoke-all",
        json={"user_id": str(fake_user_id)},
    )
    assert response.status_code == 401  # Unauthorized (no credentials)

    # Test revoke-specific without token
    response = await client.delete(f"/sessions/{uuid4()}")
    assert response.status_code == 401  # Unauthorized (no credentials)

    # Test revoke-others without token
    response = await client.post(
        "/sessions/revoke-others",
        json={"current_session_id": str(uuid4())},
    )
    assert response.status_code == 401  # Unauthorized (no credentials)
