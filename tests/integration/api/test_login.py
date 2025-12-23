import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_successful_login(client: AsyncClient):
    """AC-2.1: Successful Login

    Given a user exists with valid credentials and active membership
    When I submit login with correct email and password
    Then I receive a JWT access token scoped to my last active tenant
    And I receive a refresh token
    And I receive a list of all my tenants with roles
    And my User.last_login_at is updated
    And an AuditEvent with action=login is recorded
    """
    # First, create a user via signup
    signup_response = await client.post("/auth/signup", json={
        "email": "user@acme.com",
        "password": "SecurePass123!",
        "tenant_name": "Acme Corp"
    })
    assert signup_response.status_code == 201

    # Now attempt login
    response = await client.post("/auth/login", json={
        "email": "user@acme.com",
        "password": "SecurePass123!"
    })

    assert response.status_code == 200
    data = response.json()

    # Verify tokens
    assert "access_token" in data
    assert "refresh_token" in data
    assert isinstance(data["access_token"], str)
    assert isinstance(data["refresh_token"], str)
    assert len(data["access_token"]) > 0
    assert len(data["refresh_token"]) > 0

    # Verify active tenant
    assert "active_tenant" in data
    assert data["active_tenant"]["name"] == "Acme Corp"
    assert data["active_tenant"]["role"] == "owner"
    assert "id" in data["active_tenant"]

    # Verify other tenants list (should be empty for single tenant user)
    assert "other_tenants" in data
    assert isinstance(data["other_tenants"], list)


@pytest.mark.asyncio
async def test_login_invalid_credentials(client: AsyncClient):
    """AC-2.2: Invalid Credentials

    Given a user exists
    When I submit login with incorrect password
    Then the request fails with 401 Unauthorized
    And error code is INVALID_CREDENTIALS
    And no session is created
    """
    # First, create a user
    await client.post("/auth/signup", json={
        "email": "user@acme.com",
        "password": "SecurePass123!",
        "tenant_name": "Acme Corp"
    })

    # Attempt login with wrong password
    response = await client.post("/auth/login", json={
        "email": "user@acme.com",
        "password": "WrongPassword!"
    })

    assert response.status_code == 401
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "INVALID_CREDENTIALS"


@pytest.mark.asyncio
async def test_login_nonexistent_user(client: AsyncClient):
    """AC-2.2: Invalid Credentials (Non-existent user)

    Given no user exists with the email
    When I submit login
    Then the request fails with 401 Unauthorized
    And error code is INVALID_CREDENTIALS
    (Same error as wrong password to prevent user enumeration)
    """
    response = await client.post("/auth/login", json={
        "email": "nonexistent@acme.com",
        "password": "SomePassword123!"
    })

    assert response.status_code == 401
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "INVALID_CREDENTIALS"


@pytest.mark.asyncio
async def test_login_user_disabled(client: AsyncClient, db_session):
    """AC-2.4: User Disabled

    Given a user exists with status=disabled
    When I submit login with correct credentials
    Then the request fails with 403 Forbidden
    And error code is USER_DISABLED
    """
    # Create a user
    signup_response = await client.post("/auth/signup", json={
        "email": "disabled@acme.com",
        "password": "SecurePass123!",
        "tenant_name": "Disabled Corp"
    })
    assert signup_response.status_code == 201

    # Disable the user in database
    from src.domain.entities import User
    from sqlmodel import select

    stmt = select(User).where(User.email == "disabled@acme.com")
    result = await db_session.exec(stmt)
    user = result.one()
    user.status = "disabled"
    db_session.add(user)
    await db_session.commit()

    # Attempt login
    response = await client.post("/auth/login", json={
        "email": "disabled@acme.com",
        "password": "SecurePass123!"
    })

    assert response.status_code == 403
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "USER_DISABLED"


@pytest.mark.asyncio
async def test_login_no_active_membership(client: AsyncClient, db_session):
    """AC-2.3: No Active Membership

    Given a user has no active memberships (all revoked/deleted)
    When I submit login
    Then the request fails with 403 Forbidden
    And error code is NO_ACTIVE_MEMBERSHIP
    """
    # Create a user
    signup_response = await client.post("/auth/signup", json={
        "email": "revoked@acme.com",
        "password": "SecurePass123!",
        "tenant_name": "Revoked Corp"
    })
    assert signup_response.status_code == 201

    # Revoke the user's membership
    from src.domain.entities import Membership, User
    from sqlmodel import select

    # Get user
    stmt = select(User).where(User.email == "revoked@acme.com")
    result = await db_session.exec(stmt)
    user = result.one()

    # Revoke membership
    stmt = select(Membership).where(Membership.user_id == user.id)
    result = await db_session.exec(stmt)
    membership = result.one()
    membership.status = "revoked"
    db_session.add(membership)
    await db_session.commit()

    # Attempt login
    response = await client.post("/auth/login", json={
        "email": "revoked@acme.com",
        "password": "SecurePass123!"
    })

    assert response.status_code == 403
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "NO_ACTIVE_MEMBERSHIP"
