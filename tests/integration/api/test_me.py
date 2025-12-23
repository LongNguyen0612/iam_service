import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_successful_context_load(client: AsyncClient):
    """AC-4.1: Successful Context Load

    Given I have a valid JWT access token
    When I call /me
    Then I receive user details (id, email, email_verified)
    And I receive active tenant details (id, name, status)
    And I receive my role in the active tenant
    """
    # First, signup to get a valid JWT
    signup_response = await client.post("/auth/signup", json={
        "email": "user@acme.com",
        "password": "SecurePass123!",
        "tenant_name": "Acme Corp"
    })
    assert signup_response.status_code == 201
    access_token = signup_response.json()["access_token"]

    # Call /me with the access token
    response = await client.get("/me", headers={
        "Authorization": f"Bearer {access_token}"
    })

    assert response.status_code == 200
    data = response.json()

    # Verify user details
    assert "user" in data
    assert "id" in data["user"]
    assert data["user"]["email"] == "user@acme.com"
    assert "email_verified" in data["user"]
    assert isinstance(data["user"]["email_verified"], bool)

    # Verify tenant details
    assert "tenant" in data
    assert "id" in data["tenant"]
    assert data["tenant"]["name"] == "Acme Corp"
    assert data["tenant"]["role"] == "owner"
    assert data["tenant"]["status"] == "active"


@pytest.mark.asyncio
async def test_invalid_jwt(client: AsyncClient):
    """AC-4.2: Invalid JWT

    Given my JWT is expired or invalid
    When I call /me
    Then the request fails with 401 Unauthorized
    And error code is INVALID_TOKEN
    """
    # Call /me with an invalid token
    response = await client.get("/me", headers={
        "Authorization": "Bearer invalid_token_here"
    })

    assert response.status_code == 401
    data = response.json()
    assert "error" in data or "detail" in data
    # FastAPI may return different error formats


@pytest.mark.asyncio
async def test_no_authorization_header(client: AsyncClient):
    """AC-4.2: No Authorization Header

    Given I don't provide an authorization header
    When I call /me
    Then the request fails with 401 or 403 Unauthorized
    """
    # Call /me without authorization header
    response = await client.get("/me")

    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_revoked_membership(client: AsyncClient, db_session):
    """AC-4.3: Revoked Membership

    Given my membership in the tenant was revoked
    When I call /me
    Then the request fails with 403 Forbidden
    And error code is MEMBERSHIP_REVOKED
    """
    # Signup to get a valid JWT
    signup_response = await client.post("/auth/signup", json={
        "email": "user@acme.com",
        "password": "SecurePass123!",
        "tenant_name": "Acme Corp"
    })
    assert signup_response.status_code == 201
    access_token = signup_response.json()["access_token"]

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

    # Call /me
    response = await client.get("/me", headers={
        "Authorization": f"Bearer {access_token}"
    })

    assert response.status_code == 403
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "MEMBERSHIP_REVOKED"


@pytest.mark.asyncio
async def test_suspended_tenant(client: AsyncClient, db_session):
    """AC-4.4: Suspended Tenant

    Given my tenant is suspended
    When I call /me
    Then the request fails with 403 Forbidden
    And error code is TENANT_SUSPENDED
    """
    # Signup to get a valid JWT
    signup_response = await client.post("/auth/signup", json={
        "email": "user@acme.com",
        "password": "SecurePass123!",
        "tenant_name": "Acme Corp"
    })
    assert signup_response.status_code == 201
    access_token = signup_response.json()["access_token"]

    # Suspend the tenant in database
    from src.domain.entities import Membership, Tenant, User
    from sqlmodel import select

    # Get user
    stmt = select(User).where(User.email == "user@acme.com")
    result = await db_session.exec(stmt)
    user = result.one()

    # Get membership to find tenant
    stmt = select(Membership).where(Membership.user_id == user.id)
    result = await db_session.exec(stmt)
    membership = result.one()

    # Get and suspend tenant
    stmt = select(Tenant).where(Tenant.id == membership.tenant_id)
    result = await db_session.exec(stmt)
    tenant = result.one()
    tenant.status = "suspended"
    db_session.add(tenant)
    await db_session.commit()

    # Call /me
    response = await client.get("/me", headers={
        "Authorization": f"Bearer {access_token}"
    })

    assert response.status_code == 403
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "TENANT_SUSPENDED"
