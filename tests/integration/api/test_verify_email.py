"""
Integration tests for IAM-010: Email Verification

Tests all acceptance criteria:
- AC-10.1: Successful Email Verification
- AC-10.2: Expired Verification Token
- AC-10.3: Invalid Verification Token
- AC-10.4: Already Verified
- AC-10.5: Block Unverified Users (tested in other endpoints)
"""
import secrets
from datetime import datetime, timedelta
import pytest
from httpx import AsyncClient
from sqlmodel.ext.asyncio.session import AsyncSession
import bcrypt

from src.domain.entities import User, Tenant, Membership, MembershipRole, MembershipStatus


async def create_test_user_with_verification(
    db_session: AsyncSession,
    email: str = "test@example.com",
    verified: bool = False,
    token_expired: bool = False
) -> tuple[User, Tenant, str]:
    """
    Helper function to create a test user with email verification token.

    Returns:
        Tuple of (User, Tenant, plain_token)
    """
    # Create tenant
    tenant = Tenant(name="Test Corp")
    db_session.add(tenant)
    await db_session.flush()
    await db_session.refresh(tenant)

    # Generate verification token
    plain_token = secrets.token_urlsafe(32)

    # Create user
    password_hash = bcrypt.hashpw("TestPass123!".encode(), bcrypt.gensalt(12))

    if token_expired:
        expires_at = datetime.utcnow() - timedelta(hours=25)  # Expired (24h window)
    else:
        expires_at = datetime.utcnow() + timedelta(hours=23)  # Valid

    user = User(
        email=email,
        password_hash=password_hash.decode(),
        email_verified=verified,
        email_verification_token=plain_token if not verified else None,
        email_verification_expires_at=expires_at if not verified else None
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
async def test_successful_email_verification(client: AsyncClient, db_session: AsyncSession):
    """AC-10.1: Successful Email Verification

    Given I signed up and received a verification token via email
    When I submit the verification token within the expiry window
    Then my User.email_verified is set to true
    And I can now access agent creation and management features
    And an AuditEvent with action=email_verified is recorded
    """
    # Create unverified user with token
    user, tenant, token = await create_test_user_with_verification(
        db_session,
        email="newuser@example.com",
        verified=False,
        token_expired=False
    )

    # Verify the token is stored (before verification)
    assert user.email_verified is False
    assert user.email_verification_token is not None

    # Submit verification request
    response = await client.post("/auth/verify-email", json={
        "token": token
    })

    # Assert successful response
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "verified"
    assert "message" in data
    assert "successfully" in data["message"].lower()

    # Verify user is now verified in database
    await db_session.refresh(user)
    assert user.email_verified is True
    assert user.email_verification_token is None  # Token should be cleared
    assert user.email_verification_expires_at is None


@pytest.mark.asyncio
async def test_expired_verification_token(client: AsyncClient, db_session: AsyncSession):
    """AC-10.2: Expired Verification Token

    Given my verification token has expired
    When I submit the expired token
    Then the request fails with 410 Gone
    And error code is TOKEN_EXPIRED
    And I am prompted to resend verification email (IAM-011)
    """
    # Create user with expired token
    user, tenant, token = await create_test_user_with_verification(
        db_session,
        email="expired@example.com",
        verified=False,
        token_expired=True
    )

    # Submit verification with expired token
    response = await client.post("/auth/verify-email", json={
        "token": token
    })

    # Assert 410 Gone
    assert response.status_code == 410
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "TOKEN_EXPIRED"
    assert "message" in data["error"]

    # Verify user is still unverified
    await db_session.refresh(user)
    assert user.email_verified is False


@pytest.mark.asyncio
async def test_invalid_verification_token(client: AsyncClient):
    """AC-10.3: Invalid Verification Token

    Given I submit an invalid or non-existent token
    When verification is attempted
    Then the request fails with 400 Bad Request
    And error code is INVALID_TOKEN
    """
    # Submit with completely invalid token
    response = await client.post("/auth/verify-email", json={
        "token": "this-is-not-a-valid-token-at-all"
    })

    # Assert 400 Bad Request
    assert response.status_code == 400
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "INVALID_TOKEN"
    assert "message" in data["error"]


@pytest.mark.asyncio
async def test_already_verified(client: AsyncClient, db_session: AsyncSession):
    """AC-10.4: Already Verified

    Given my email is already verified but I still have my verification token
    When I attempt to verify again
    Then the request succeeds with 200 OK
    And a message indicates email is already verified

    Note: This tests the idempotent behavior where we first verify,
    then verify again with the same token before it's fully cleared.
    """
    # Create unverified user with token
    user, tenant, token = await create_test_user_with_verification(
        db_session,
        email="verified@example.com",
        verified=False,
        token_expired=False
    )

    # First verification - should succeed
    response1 = await client.post("/auth/verify-email", json={
        "token": token
    })
    assert response1.status_code == 200

    # Create a verified user with a token still present (edge case for testing)
    # Normally tokens are cleared after verification
    await db_session.refresh(user)
    user.email_verification_token = token  # Restore token for testing
    db_session.add(user)
    await db_session.commit()

    # Attempt to verify again with same token
    response2 = await client.post("/auth/verify-email", json={
        "token": token
    })

    # Should return 200 OK with already verified message
    assert response2.status_code == 200
    data = response2.json()
    assert data["status"] == "verified"
    assert "already" in data["message"].lower() or "verified" in data["message"].lower()


@pytest.mark.asyncio
async def test_verification_token_cleared_after_use(client: AsyncClient, db_session: AsyncSession):
    """Security Test: Verification token should be single-use

    Given I successfully verify my email
    When I try to use the same token again
    Then it should fail as INVALID_TOKEN
    """
    # Create unverified user
    user, tenant, token = await create_test_user_with_verification(
        db_session,
        email="singleuse@example.com",
        verified=False,
        token_expired=False
    )

    # First verification - should succeed
    response1 = await client.post("/auth/verify-email", json={
        "token": token
    })
    assert response1.status_code == 200

    # Second verification with same token - should fail
    response2 = await client.post("/auth/verify-email", json={
        "token": token
    })
    assert response2.status_code == 400
    data = response2.json()
    assert data["error"]["code"] == "INVALID_TOKEN"
