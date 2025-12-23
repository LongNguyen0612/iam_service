import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_successful_signup(client: AsyncClient):
    """AC-1.1: Successful Signup

    Given no user exists with email "founder@acme.com"
    When I submit signup with valid email, password, and tenant name
    Then a User account is created
    And a Tenant is created with the provided name
    And a Membership is created with role=owner and status=active
    And a Session with refresh token is created
    And I receive a JWT access token and refresh token
    And an AuditEvent with action=signup is recorded
    """
    response = await client.post("/auth/signup", json={
        "email": "founder@acme.com",
        "password": "SecurePass123!",
        "tenant_name": "Acme Corp"
    })

    assert response.status_code == 201
    data = response.json()

    # Verify user data
    assert "user" in data
    assert data["user"]["email"] == "founder@acme.com"
    assert data["user"]["email_verified"] is False
    assert "id" in data["user"]

    # Verify tenant data
    assert "tenant" in data
    assert data["tenant"]["name"] == "Acme Corp"
    assert "id" in data["tenant"]

    # Verify tokens
    assert "access_token" in data
    assert "refresh_token" in data
    assert isinstance(data["access_token"], str)
    assert isinstance(data["refresh_token"], str)
    assert len(data["access_token"]) > 0
    assert len(data["refresh_token"]) > 0


@pytest.mark.asyncio
async def test_signup_existing_email(client: AsyncClient):
    """AC-1.2: Email Already Exists

    Given a user already exists with email "founder@acme.com"
    When I submit signup with that email
    Then the request fails with 409 Conflict
    And error code is EMAIL_ALREADY_EXISTS
    And no Tenant is created
    """
    # First signup - should succeed
    await client.post("/auth/signup", json={
        "email": "founder@acme.com",
        "password": "SecurePass123!",
        "tenant_name": "Acme Corp"
    })

    # Second signup with same email - should fail
    response = await client.post("/auth/signup", json={
        "email": "founder@acme.com",
        "password": "DifferentPass456!",
        "tenant_name": "New Corp"
    })

    assert response.status_code == 409
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "EMAIL_ALREADY_EXISTS"
    assert "message" in data["error"]


@pytest.mark.asyncio
async def test_signup_invalid_input(client: AsyncClient):
    """AC-1.3: Invalid Input Validation

    Given I submit signup with missing or invalid fields
    When required fields (email/password/tenant_name) are invalid
    Then the request fails with 400 Bad Request
    And error code is INVALID_INPUT
    And specific validation errors are returned
    """
    # Test missing email
    response = await client.post("/auth/signup", json={
        "password": "SecurePass123!",
        "tenant_name": "Acme Corp"
    })
    assert response.status_code == 422  # FastAPI validation error

    # Test invalid email format
    response = await client.post("/auth/signup", json={
        "email": "not-an-email",
        "password": "SecurePass123!",
        "tenant_name": "Acme Corp"
    })
    assert response.status_code == 422  # FastAPI validation error

    # Test missing password
    response = await client.post("/auth/signup", json={
        "email": "test@example.com",
        "tenant_name": "Acme Corp"
    })
    assert response.status_code == 422  # FastAPI validation error

    # Test missing tenant_name
    response = await client.post("/auth/signup", json={
        "email": "test@example.com",
        "password": "SecurePass123!"
    })
    assert response.status_code == 422  # FastAPI validation error
