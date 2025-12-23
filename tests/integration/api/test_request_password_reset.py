"""
Integration tests for IAM-012: Request Password Reset

Tests all acceptance criteria:
- AC-12.1: Successful Password Reset Request
- AC-12.2: No Email Enumeration
- AC-12.3: Rate Limiting (tested at middleware layer)
"""
import hashlib
from datetime import datetime, timedelta
import pytest
from httpx import AsyncClient
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
import bcrypt

from src.domain.entities import User, Tenant, Membership, MembershipRole, MembershipStatus, PasswordResetToken


async def create_test_user_for_password_reset(
    db_session: AsyncSession,
    email: str = "test@example.com",
) -> tuple[User, Tenant]:
    """
    Helper function to create a test user for password reset tests.

    Returns:
        Tuple of (User, Tenant)
    """
    # Create tenant
    tenant = Tenant(name="Test Corp")
    db_session.add(tenant)
    await db_session.flush()
    await db_session.refresh(tenant)

    # Create user
    password_hash = bcrypt.hashpw("TestPass123!".encode(), bcrypt.gensalt(12))

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
    await db_session.commit()

    return user, tenant


@pytest.mark.asyncio
async def test_successful_password_reset_request(client: AsyncClient, db_session: AsyncSession):
    """AC-12.1: Successful Password Reset Request

    Given I have an account
    When I request a password reset
    Then a secure reset token is generated
    And the token is hashed with SHA-256 before storing
    And the token expires in 1 hour
    And a password reset email is sent (stubbed)
    """
    # Create test user
    user, tenant = await create_test_user_for_password_reset(
        db_session,
        email="reset@example.com"
    )

    # Request password reset
    response = await client.post("/auth/request-password-reset", json={
        "email": "reset@example.com"
    })

    # Assert successful response
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "sent"
    assert "message" in data

    # Verify password reset token was created in database
    stmt = select(PasswordResetToken).where(PasswordResetToken.user_id == user.id)
    result = await db_session.exec(stmt)
    reset_token = result.one_or_none()

    assert reset_token is not None
    assert reset_token.user_id == user.id
    assert reset_token.used is False
    assert len(reset_token.token_hash) == 64  # SHA-256 hex digest is 64 chars

    # Verify expiry is set to ~1 hour from now
    time_until_expiry = reset_token.expires_at - datetime.utcnow()
    assert time_until_expiry.total_seconds() > 55 * 60  # At least 55 minutes
    assert time_until_expiry.total_seconds() < 65 * 60  # Less than 65 minutes


@pytest.mark.asyncio
async def test_password_reset_non_existent_email(client: AsyncClient, db_session: AsyncSession):
    """AC-12.2: No Email Enumeration

    Given no user exists with the provided email
    When I request password reset
    Then the request succeeds (no enumeration)
    And no token is created
    And the response is identical to success case
    """
    # Request reset for non-existent email
    response = await client.post("/auth/request-password-reset", json={
        "email": "nonexistent@example.com"
    })

    # Assert successful response (no enumeration)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "sent"
    assert "message" in data

    # Verify no token was created
    stmt = select(PasswordResetToken)
    result = await db_session.exec(stmt)
    tokens = result.all()
    assert len(tokens) == 0  # No tokens should exist


@pytest.mark.asyncio
async def test_password_reset_token_is_hashed(client: AsyncClient, db_session: AsyncSession):
    """Security Test: Token should be hashed with SHA-256

    Given I request a password reset
    Then the token stored in database should be a SHA-256 hash
    And the hash should be 64 characters (hex digest)
    """
    # Create test user
    user, tenant = await create_test_user_for_password_reset(
        db_session,
        email="hashed@example.com"
    )

    # Request password reset
    response = await client.post("/auth/request-password-reset", json={
        "email": "hashed@example.com"
    })
    assert response.status_code == 200

    # Get token from database
    stmt = select(PasswordResetToken).where(PasswordResetToken.user_id == user.id)
    result = await db_session.exec(stmt)
    reset_token = result.one()

    # Verify token is hashed
    assert len(reset_token.token_hash) == 64  # SHA-256 hex digest
    # Token should be hexadecimal
    try:
        int(reset_token.token_hash, 16)
        is_hex = True
    except ValueError:
        is_hex = False
    assert is_hex


@pytest.mark.asyncio
async def test_password_reset_multiple_requests(client: AsyncClient, db_session: AsyncSession):
    """Business Logic Test: Multiple requests create multiple tokens

    Given I have already requested a password reset
    When I request another password reset
    Then a new token should be created
    And both tokens should exist in the database
    """
    # Create test user
    user, tenant = await create_test_user_for_password_reset(
        db_session,
        email="multiple@example.com"
    )

    # First request
    response1 = await client.post("/auth/request-password-reset", json={
        "email": "multiple@example.com"
    })
    assert response1.status_code == 200

    # Second request
    response2 = await client.post("/auth/request-password-reset", json={
        "email": "multiple@example.com"
    })
    assert response2.status_code == 200

    # Verify both tokens exist
    stmt = select(PasswordResetToken).where(PasswordResetToken.user_id == user.id)
    result = await db_session.exec(stmt)
    tokens = result.all()
    assert len(tokens) == 2  # Both tokens should exist


@pytest.mark.asyncio
async def test_password_reset_invalid_email_format(client: AsyncClient):
    """Input Validation: Invalid email format should be rejected

    Given I provide an invalid email format
    When I request password reset
    Then the request should fail with 422 Unprocessable Entity
    """
    # Request reset with invalid email
    response = await client.post("/auth/request-password-reset", json={
        "email": "not-a-valid-email"
    })

    # Assert validation error
    assert response.status_code == 422  # FastAPI validation error


@pytest.mark.asyncio
async def test_password_reset_creates_audit_event(client: AsyncClient, db_session: AsyncSession):
    """Security Test: Audit event should be created

    Given I request a password reset
    Then an audit event should be created for security tracking
    And the event should contain relevant metadata
    """
    from src.domain.entities import AuditEvent

    # Create test user
    user, tenant = await create_test_user_for_password_reset(
        db_session,
        email="audit@example.com"
    )

    # Request password reset
    response = await client.post("/auth/request-password-reset", json={
        "email": "audit@example.com"
    })
    assert response.status_code == 200

    # Verify audit event was created
    stmt = select(AuditEvent).where(
        AuditEvent.user_id == user.id,
        AuditEvent.action == "password_reset_requested"
    )
    result = await db_session.exec(stmt)
    audit_event = result.one_or_none()

    assert audit_event is not None
    assert audit_event.user_id == user.id
    assert audit_event.action == "password_reset_requested"
    assert "email" in audit_event.event_metadata
    assert audit_event.event_metadata["email"] == "audit@example.com"
