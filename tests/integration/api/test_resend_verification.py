"""
Integration tests for IAM-011: Resend Verification Email

Tests all acceptance criteria:
- AC-11.1: Successful Resend
- AC-11.2: Already Verified
- AC-11.3: Rate Limiting (tested at middleware layer)
"""
import secrets
from datetime import datetime, timedelta
import pytest
from httpx import AsyncClient
from sqlmodel.ext.asyncio.session import AsyncSession
import bcrypt

from src.domain.entities import User, Tenant, Membership, MembershipRole, MembershipStatus


async def create_test_user_for_resend(
    db_session: AsyncSession,
    email: str = "test@example.com",
    verified: bool = False,
    with_token: bool = True
) -> tuple[User, Tenant, str | None]:
    """
    Helper function to create a test user for resend verification tests.

    Returns:
        Tuple of (User, Tenant, plain_token_or_none)
    """
    # Create tenant
    tenant = Tenant(name="Test Corp")
    db_session.add(tenant)
    await db_session.flush()
    await db_session.refresh(tenant)

    # Generate verification token if needed
    plain_token = secrets.token_urlsafe(32) if with_token else None

    # Create user
    password_hash = bcrypt.hashpw("TestPass123!".encode(), bcrypt.gensalt(12))

    user = User(
        email=email,
        password_hash=password_hash.decode(),
        email_verified=verified,
        email_verification_token=plain_token if with_token and not verified else None,
        email_verification_expires_at=(datetime.utcnow() + timedelta(hours=23)) if with_token and not verified else None
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

    return user, tenant, plain_token


@pytest.mark.asyncio
async def test_successful_resend_verification(client: AsyncClient, db_session: AsyncSession):
    """AC-11.1: Successful Resend

    Given my email is not yet verified
    When I request a new verification email
    Then a new token is generated and replaces the old one
    And a new verification email is sent
    And the token expiry is reset to 24 hours from now
    """
    # Create unverified user with existing token
    user, tenant, old_token = await create_test_user_for_resend(
        db_session,
        email="unverified@example.com",
        verified=False,
        with_token=True
    )

    # Store old token and expiry for comparison
    old_token_value = user.email_verification_token
    old_expiry = user.email_verification_expires_at

    # Request resend
    response = await client.post("/auth/resend-verification", json={
        "email": "unverified@example.com"
    })

    # Assert successful response
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "sent"
    assert "message" in data

    # Verify new token was generated and old one replaced
    await db_session.refresh(user)
    assert user.email_verification_token is not None
    assert user.email_verification_token != old_token_value  # New token, not old one
    assert user.email_verification_expires_at is not None
    assert user.email_verification_expires_at > old_expiry  # Expiry extended
    assert user.email_verified is False  # Still not verified


@pytest.mark.asyncio
async def test_resend_already_verified(client: AsyncClient, db_session: AsyncSession):
    """AC-11.2: Already Verified

    Given my email is already verified
    When I request resend
    Then the request succeeds but no email is sent
    And a message indicates email is already verified
    """
    # Create already verified user
    user, tenant, _ = await create_test_user_for_resend(
        db_session,
        email="verified@example.com",
        verified=True,
        with_token=False
    )

    # Request resend for verified user
    response = await client.post("/auth/resend-verification", json={
        "email": "verified@example.com"
    })

    # Assert successful response with already verified status
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "already_verified"
    assert "already" in data["message"].lower() or "verified" in data["message"].lower()

    # Verify user remains verified and no token was generated
    await db_session.refresh(user)
    assert user.email_verified is True
    assert user.email_verification_token is None
    assert user.email_verification_expires_at is None


@pytest.mark.asyncio
async def test_resend_non_existent_email(client: AsyncClient):
    """Security Test: No Email Enumeration

    Given no user exists with the provided email
    When I request password reset
    Then the request succeeds (no enumeration)
    And no email is sent
    And the response is identical to success case
    """
    # Request resend for non-existent email
    response = await client.post("/auth/resend-verification", json={
        "email": "nonexistent@example.com"
    })

    # Assert successful response (no enumeration)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "sent"
    assert "message" in data
    # Same message as valid email to prevent enumeration


@pytest.mark.asyncio
async def test_resend_invalidates_old_token(client: AsyncClient, db_session: AsyncSession):
    """Security Test: Old token should be invalidated

    Given I have an unverified account with a verification token
    When I request a new verification email
    Then the old token should be replaced and no longer work
    And the new token should work for verification
    """
    # Create unverified user
    user, tenant, old_token = await create_test_user_for_resend(
        db_session,
        email="tokentest@example.com",
        verified=False,
        with_token=True
    )

    # Store old token
    old_token_value = user.email_verification_token

    # Request resend
    response = await client.post("/auth/resend-verification", json={
        "email": "tokentest@example.com"
    })
    assert response.status_code == 200

    # Get new token from database
    await db_session.refresh(user)
    new_token_value = user.email_verification_token

    # Verify old and new tokens are different
    assert new_token_value != old_token_value

    # Try to verify with old token - should fail
    old_verify_response = await client.post("/auth/verify-email", json={
        "token": old_token_value
    })
    assert old_verify_response.status_code == 400
    assert old_verify_response.json()["error"]["code"] == "INVALID_TOKEN"

    # Try to verify with new token - should succeed
    new_verify_response = await client.post("/auth/verify-email", json={
        "token": new_token_value
    })
    assert new_verify_response.status_code == 200
    assert new_verify_response.json()["status"] == "verified"


@pytest.mark.asyncio
async def test_resend_extends_expiry(client: AsyncClient, db_session: AsyncSession):
    """Business Logic Test: Resend should reset expiry to 24 hours from now

    Given my verification token expires in 1 hour
    When I request resend
    Then the expiry should be reset to ~24 hours from now
    """
    # Create unverified user with token expiring soon
    user, tenant, _ = await create_test_user_for_resend(
        db_session,
        email="expiring@example.com",
        verified=False,
        with_token=True
    )

    # Manually set expiry to 1 hour from now (almost expired)
    user.email_verification_expires_at = datetime.utcnow() + timedelta(hours=1)
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    old_expiry = user.email_verification_expires_at

    # Request resend
    response = await client.post("/auth/resend-verification", json={
        "email": "expiring@example.com"
    })
    assert response.status_code == 200

    # Verify expiry was extended
    await db_session.refresh(user)
    new_expiry = user.email_verification_expires_at

    # New expiry should be ~24 hours from now (at least 23 hours)
    time_until_expiry = new_expiry - datetime.utcnow()
    assert time_until_expiry.total_seconds() > 23 * 3600  # At least 23 hours
    assert time_until_expiry.total_seconds() < 25 * 3600  # Less than 25 hours


@pytest.mark.asyncio
async def test_resend_invalid_email_format(client: AsyncClient):
    """Input Validation: Invalid email format should be rejected

    Given I provide an invalid email format
    When I request resend
    Then the request should fail with 422 Unprocessable Entity
    """
    # Request resend with invalid email
    response = await client.post("/auth/resend-verification", json={
        "email": "not-a-valid-email"
    })

    # Assert validation error
    assert response.status_code == 422  # FastAPI validation error
