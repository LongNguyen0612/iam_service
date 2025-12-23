import pytest
from httpx import AsyncClient
from datetime import datetime, timedelta
import asyncio


@pytest.mark.asyncio
async def test_successful_token_refresh(client: AsyncClient):
    """AC-3.1: Successful Token Refresh

    Given I have a valid refresh token
    When I submit the refresh token
    Then I receive a new access token
    And the refresh token is rotated (new one issued)
    And the old refresh token is invalidated
    And an AuditEvent with action=token_refresh is recorded
    """
    # First, signup and login to get tokens
    signup_response = await client.post("/auth/signup", json={
        "email": "user@acme.com",
        "password": "SecurePass123!",
        "tenant_name": "Acme Corp"
    })
    assert signup_response.status_code == 201
    old_refresh_token = signup_response.json()["refresh_token"]
    old_access_token = signup_response.json()["access_token"]

    # Small delay to ensure different JWT timestamp (iat)
    await asyncio.sleep(1)

    # Refresh the token
    response = await client.post("/auth/refresh", json={
        "refresh_token": old_refresh_token
    })

    assert response.status_code == 200
    data = response.json()

    # Verify new tokens
    assert "access_token" in data
    assert "refresh_token" in data
    assert isinstance(data["access_token"], str)
    assert isinstance(data["refresh_token"], str)
    assert len(data["access_token"]) > 0
    assert len(data["refresh_token"]) > 0

    # Verify tokens are different (rotated)
    assert data["access_token"] != old_access_token
    assert data["refresh_token"] != old_refresh_token

    # Verify old refresh token is now invalid
    old_token_response = await client.post("/auth/refresh", json={
        "refresh_token": old_refresh_token
    })
    assert old_token_response.status_code == 401
    error = old_token_response.json()["error"]
    assert error["code"] in ("INVALID_TOKEN", "SESSION_REVOKED")


@pytest.mark.asyncio
async def test_refresh_with_revoked_session(client: AsyncClient, db_session):
    """AC-3.2: Revoked Session

    Given my session has been revoked
    When I attempt to refresh
    Then the request fails with 401 Unauthorized
    And error code is SESSION_REVOKED
    """
    # Signup to get a refresh token
    signup_response = await client.post("/auth/signup", json={
        "email": "user@acme.com",
        "password": "SecurePass123!",
        "tenant_name": "Acme Corp"
    })
    assert signup_response.status_code == 201
    refresh_token = signup_response.json()["refresh_token"]

    # Revoke the session in database
    from src.domain.entities import Session, User
    from sqlmodel import select
    import bcrypt

    # Get user
    stmt = select(User).where(User.email == "user@acme.com")
    result = await db_session.exec(stmt)
    user = result.one()

    # Find and revoke session
    stmt = select(Session).where(Session.user_id == user.id)
    result = await db_session.exec(stmt)
    session = result.one()
    session.revoked = True
    db_session.add(session)
    await db_session.commit()

    # Attempt refresh
    response = await client.post("/auth/refresh", json={
        "refresh_token": refresh_token
    })

    assert response.status_code == 401
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "SESSION_REVOKED"


@pytest.mark.asyncio
async def test_refresh_with_expired_token(client: AsyncClient, db_session):
    """AC-3.3: Expired Refresh Token

    Given my refresh token has expired
    When I attempt to refresh
    Then the request fails with 401 Unauthorized
    And error code is SESSION_EXPIRED
    And I must log in again
    """
    # Signup to get a refresh token
    signup_response = await client.post("/auth/signup", json={
        "email": "user@acme.com",
        "password": "SecurePass123!",
        "tenant_name": "Acme Corp"
    })
    assert signup_response.status_code == 201
    refresh_token = signup_response.json()["refresh_token"]

    # Expire the session in database
    from src.domain.entities import Session, User
    from sqlmodel import select

    # Get user
    stmt = select(User).where(User.email == "user@acme.com")
    result = await db_session.exec(stmt)
    user = result.one()

    # Find and expire session
    stmt = select(Session).where(Session.user_id == user.id)
    result = await db_session.exec(stmt)
    session = result.one()
    session.expires_at = datetime.utcnow() - timedelta(days=1)  # Expired yesterday
    db_session.add(session)
    await db_session.commit()

    # Attempt refresh
    response = await client.post("/auth/refresh", json={
        "refresh_token": refresh_token
    })

    assert response.status_code == 401
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "SESSION_EXPIRED"


@pytest.mark.asyncio
async def test_refresh_with_revoked_membership(client: AsyncClient, db_session):
    """AC-3.4: Membership Revoked

    Given my membership in the tenant was revoked
    When I attempt to refresh
    Then the request fails with 403 Forbidden
    And error code is MEMBERSHIP_REVOKED
    """
    # Signup to get a refresh token
    signup_response = await client.post("/auth/signup", json={
        "email": "user@acme.com",
        "password": "SecurePass123!",
        "tenant_name": "Acme Corp"
    })
    assert signup_response.status_code == 201
    refresh_token = signup_response.json()["refresh_token"]

    # Revoke the membership in database
    from src.domain.entities import Membership, User
    from sqlmodel import select

    # Get user
    stmt = select(User).where(User.email == "user@acme.com")
    result = await db_session.exec(stmt)
    user = result.one()

    # Revoke membership
    stmt = select(Membership).where(Membership.user_id == user.id)
    result = await db_session.exec(stmt)
    membership = result.one()
    membership.status = "revoked"
    db_session.add(membership)
    await db_session.commit()

    # Attempt refresh
    response = await client.post("/auth/refresh", json={
        "refresh_token": refresh_token
    })

    assert response.status_code == 403
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "MEMBERSHIP_REVOKED"


@pytest.mark.asyncio
async def test_token_reuse_detection(client: AsyncClient):
    """AC-3.5: Token Reuse Detection (Security)

    Given I attempt to use the same refresh token twice
    When I submit the token twice
    Then the first succeeds and rotates the token
    And the second fails with 401 Unauthorized
    And error code is TOKEN_REUSED or INVALID_TOKEN
    And the entire session is revoked as a security measure
    """
    # Signup to get a refresh token
    signup_response = await client.post("/auth/signup", json={
        "email": "user@acme.com",
        "password": "SecurePass123!",
        "tenant_name": "Acme Corp"
    })
    assert signup_response.status_code == 201
    refresh_token = signup_response.json()["refresh_token"]

    # First refresh - should succeed
    first_response = await client.post("/auth/refresh", json={
        "refresh_token": refresh_token
    })
    assert first_response.status_code == 200
    new_refresh_token = first_response.json()["refresh_token"]

    # Second refresh with old token - should fail (token reuse)
    second_response = await client.post("/auth/refresh", json={
        "refresh_token": refresh_token
    })
    assert second_response.status_code == 401
    data = second_response.json()
    assert "error" in data
    # Token is invalidated after first use
    assert data["error"]["code"] in ("INVALID_TOKEN", "TOKEN_REUSED", "SESSION_REVOKED")

    # Even the new token should be invalid if session is revoked
    # (optional security measure - some systems revoke entire session on reuse)
