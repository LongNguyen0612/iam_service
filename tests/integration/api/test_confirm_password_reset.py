"""
Integration tests for IAM-013: Confirm Password Reset

Tests all acceptance criteria:
- AC-13.1: Successful Password Reset Confirmation
- AC-13.2: Invalid Token Handling
- AC-13.3: Expired Token Handling
- AC-13.4: Password Validation
"""
import hashlib
import secrets
from datetime import datetime, timedelta
import pytest
from httpx import AsyncClient
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
import bcrypt

from src.domain.entities import User, Tenant, Membership, MembershipRole, MembershipStatus, PasswordResetToken, Session


async def create_test_user_with_reset_token(
    db_session: AsyncSession,
    email: str = "test@example.com",
    expired: bool = False,
    used: bool = False,
) -> tuple[User, Tenant, str, str]:
    """
    Helper function to create a test user with password reset token.

    Returns:
        Tuple of (User, Tenant, plain_token, token_hash)
    """
    # Create tenant
    tenant = Tenant(name="Test Corp")
    db_session.add(tenant)
    await db_session.flush()
    await db_session.refresh(tenant)

    # Create user
    password_hash = bcrypt.hashpw("OldPass123!".encode(), bcrypt.gensalt(12))

    user = User(
        email=email,
        password_hash=password_hash.decode(),
        email_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    await db_session.refresh(user)

    # Create membership
    membership = Membership(
        user_id=user.id,
        tenant_id=tenant.id,
        role=MembershipRole.owner,
        status=MembershipStatus.active
    )
    db_session.add(membership)
    await db_session.flush()

    # Generate reset token
    plain_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(plain_token.encode()).hexdigest()

    # Create password reset token
    expires_at = datetime.utcnow() - timedelta(hours=2) if expired else datetime.utcnow() + timedelta(minutes=30)

    reset_token = PasswordResetToken(
        user_id=user.id,
        token_hash=token_hash,
        used=used,
        expires_at=expires_at,
    )
    db_session.add(reset_token)
    await db_session.commit()

    return user, tenant, plain_token, token_hash


@pytest.mark.asyncio
async def test_successful_password_reset_confirmation(client: AsyncClient, db_session: AsyncSession):
    """AC-13.1: Successful Password Reset Confirmation

    Given I have a valid password reset token
    When I confirm the reset with a new password
    Then my password is updated
    And the token is marked as used
    And all my sessions are revoked
    And I can login with the new password
    """
    # Create test user with reset token
    user, tenant, plain_token, token_hash = await create_test_user_with_reset_token(
        db_session,
        email="reset@example.com"
    )

    # Create a session for the user (to test revocation)
    refresh_token_hash = bcrypt.hashpw("refresh_token".encode(), bcrypt.gensalt(12))
    session = Session(
        user_id=user.id,
        tenant_id=tenant.id,
        refresh_token_hash=refresh_token_hash.decode(),
        expires_at=datetime.utcnow() + timedelta(days=30),
        revoked=False,
    )
    db_session.add(session)
    await db_session.commit()

    # Confirm password reset
    new_password = "NewSecurePass123!"
    response = await client.post("/auth/confirm-password-reset", json={
        "token": plain_token,
        "new_password": new_password
    })

    # Assert successful response
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "message" in data

    # Verify password was updated
    await db_session.refresh(user)
    assert bcrypt.checkpw(new_password.encode(), user.password_hash.encode())

    # Verify token was marked as used
    stmt = select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash)
    result = await db_session.exec(stmt)
    reset_token = result.one()
    assert reset_token.used is True

    # Verify all sessions were revoked
    await db_session.refresh(session)
    assert session.revoked is True


@pytest.mark.asyncio
async def test_invalid_token(client: AsyncClient, db_session: AsyncSession):
    """AC-13.2: Invalid Token Handling

    Given I provide an invalid reset token
    When I attempt to confirm reset
    Then the request fails with 400 Bad Request
    And the error indicates invalid token
    """
    # Use a random token that doesn't exist
    invalid_token = secrets.token_urlsafe(32)

    response = await client.post("/auth/confirm-password-reset", json={
        "token": invalid_token,
        "new_password": "NewPass123!"
    })

    # Assert error response
    assert response.status_code == 400
    data = response.json()
    assert data["error"]["code"] == "INVALID_TOKEN"


@pytest.mark.asyncio
async def test_expired_token(client: AsyncClient, db_session: AsyncSession):
    """AC-13.3: Expired Token Handling

    Given I have an expired reset token
    When I attempt to confirm reset
    Then the request fails with 410 Gone
    And the error indicates token expired
    """
    # Create user with expired token
    user, tenant, plain_token, token_hash = await create_test_user_with_reset_token(
        db_session,
        email="expired@example.com",
        expired=True
    )

    response = await client.post("/auth/confirm-password-reset", json={
        "token": plain_token,
        "new_password": "NewPass123!"
    })

    # Assert error response
    assert response.status_code == 410
    data = response.json()
    assert data["error"]["code"] == "TOKEN_EXPIRED"


@pytest.mark.asyncio
async def test_already_used_token(client: AsyncClient, db_session: AsyncSession):
    """Security Test: Token Already Used

    Given I have already used a reset token
    When I attempt to use it again
    Then the request fails with 409 Conflict
    And the error indicates token already used
    """
    # Create user with used token
    user, tenant, plain_token, token_hash = await create_test_user_with_reset_token(
        db_session,
        email="used@example.com",
        used=True
    )

    response = await client.post("/auth/confirm-password-reset", json={
        "token": plain_token,
        "new_password": "NewPass123!"
    })

    # Assert error response
    assert response.status_code == 409
    data = response.json()
    assert data["error"]["code"] == "TOKEN_ALREADY_USED"


@pytest.mark.asyncio
async def test_password_too_short(client: AsyncClient, db_session: AsyncSession):
    """AC-13.4: Password Validation - Too Short

    Given I have a valid reset token
    When I provide a password that's too short
    Then the request fails with 400 Bad Request
    And the error indicates invalid password
    """
    # Create user with reset token
    user, tenant, plain_token, token_hash = await create_test_user_with_reset_token(
        db_session,
        email="short@example.com"
    )

    response = await client.post("/auth/confirm-password-reset", json={
        "token": plain_token,
        "new_password": "short"  # Too short
    })

    # Assert validation error (FastAPI validation or use case validation)
    assert response.status_code in [400, 422]


@pytest.mark.asyncio
async def test_sessions_revoked_after_reset(client: AsyncClient, db_session: AsyncSession):
    """Security Test: All Sessions Revoked

    Given I have multiple active sessions
    When I confirm password reset
    Then all my sessions should be revoked
    """
    # Create user with reset token
    user, tenant, plain_token, token_hash = await create_test_user_with_reset_token(
        db_session,
        email="sessions@example.com"
    )

    # Create multiple sessions
    for i in range(3):
        refresh_token_hash = bcrypt.hashpw(f"refresh_token_{i}".encode(), bcrypt.gensalt(12))
        session = Session(
            user_id=user.id,
            tenant_id=tenant.id,
            refresh_token_hash=refresh_token_hash.decode(),
            expires_at=datetime.utcnow() + timedelta(days=30),
            revoked=False,
        )
        db_session.add(session)
    await db_session.commit()

    # Confirm password reset
    response = await client.post("/auth/confirm-password-reset", json={
        "token": plain_token,
        "new_password": "NewPass123!"
    })
    assert response.status_code == 200

    # Verify all sessions were revoked
    stmt = select(Session).where(Session.user_id == user.id)
    result = await db_session.exec(stmt)
    sessions = result.all()
    assert len(sessions) == 3
    assert all(s.revoked for s in sessions)


@pytest.mark.asyncio
async def test_password_reset_creates_audit_event(client: AsyncClient, db_session: AsyncSession):
    """Security Test: Audit Event Created

    Given I confirm a password reset
    Then an audit event should be created
    And it should contain relevant metadata
    """
    from src.domain.entities import AuditEvent

    # Create user with reset token
    user, tenant, plain_token, token_hash = await create_test_user_with_reset_token(
        db_session,
        email="audit@example.com"
    )

    # Confirm password reset
    response = await client.post("/auth/confirm-password-reset", json={
        "token": plain_token,
        "new_password": "NewPass123!"
    })
    assert response.status_code == 200

    # Verify audit event was created
    stmt = select(AuditEvent).where(
        AuditEvent.user_id == user.id,
        AuditEvent.action == "password_reset_confirmed"
    )
    result = await db_session.exec(stmt)
    audit_event = result.one_or_none()

    assert audit_event is not None
    assert audit_event.user_id == user.id
    assert audit_event.action == "password_reset_confirmed"
    assert "token_id" in audit_event.event_metadata
    assert "sessions_revoked" in audit_event.event_metadata


@pytest.mark.asyncio
async def test_can_login_with_new_password(client: AsyncClient, db_session: AsyncSession):
    """Integration Test: Login After Reset

    Given I have reset my password
    When I attempt to login with the new password
    Then I should successfully authenticate
    """
    # Create user with reset token
    user, tenant, plain_token, token_hash = await create_test_user_with_reset_token(
        db_session,
        email="login@example.com"
    )

    new_password = "NewLoginPass123!"

    # Confirm password reset
    response = await client.post("/auth/confirm-password-reset", json={
        "token": plain_token,
        "new_password": new_password
    })
    assert response.status_code == 200

    # Attempt login with new password
    login_response = await client.post("/auth/login", json={
        "email": "login@example.com",
        "password": new_password
    })

    # Should successfully login
    assert login_response.status_code == 200
    login_data = login_response.json()
    assert "access_token" in login_data
    assert "refresh_token" in login_data


@pytest.mark.asyncio
async def test_cannot_login_with_old_password(client: AsyncClient, db_session: AsyncSession):
    """Security Test: Old Password Invalid After Reset

    Given I have reset my password
    When I attempt to login with the old password
    Then I should be rejected
    """
    # Create user with reset token
    user, tenant, plain_token, token_hash = await create_test_user_with_reset_token(
        db_session,
        email="oldpass@example.com"
    )

    # Confirm password reset
    response = await client.post("/auth/confirm-password-reset", json={
        "token": plain_token,
        "new_password": "NewPass123!"
    })
    assert response.status_code == 200

    # Attempt login with old password
    login_response = await client.post("/auth/login", json={
        "email": "oldpass@example.com",
        "password": "OldPass123!"  # Old password
    })

    # Should fail
    assert login_response.status_code == 401
