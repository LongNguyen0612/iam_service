from datetime import UTC, datetime, timedelta
from typing import Optional
from uuid import UUID

from jose import JWTError, jwt

from config import ApplicationConfig


def generate_jwt(user_id: UUID, tenant_id: UUID, role: str) -> str:
    """
    Generate JWT access token

    Args:
        user_id: User UUID
        tenant_id: Tenant UUID
        role: User role (owner, admin, member)

    Returns:
        JWT token string (HS256, 15-minute expiry)
    """
    now = datetime.now(UTC)
    payload = {
        "user_id": str(user_id),
        "tenant_id": str(tenant_id),
        "role": role,
        "exp": now + timedelta(minutes=15),
        "iat": now,
    }
    return jwt.encode(payload, ApplicationConfig.JWT_SECRET, algorithm="HS256")


def create_access_token(
    user_id: str, tenant_id: str, role: str, expires_delta: timedelta
) -> str:
    """
    Create JWT access token with custom expiry

    Args:
        user_id: User UUID as string
        tenant_id: Tenant UUID as string
        role: User role (owner, admin, member)
        expires_delta: Token expiration duration

    Returns:
        JWT token string (HS256)
    """
    now = datetime.now(UTC)
    payload = {
        "user_id": user_id,
        "tenant_id": tenant_id,
        "role": role,
        "exp": now + expires_delta,
        "iat": now,
    }
    return jwt.encode(payload, ApplicationConfig.JWT_SECRET, algorithm="HS256")


def verify_jwt(token: str) -> Optional[dict]:
    """
    Verify and decode JWT token

    Args:
        token: JWT token string

    Returns:
        Decoded payload dict or None if invalid
    """
    try:
        payload = jwt.decode(
            token, ApplicationConfig.JWT_SECRET, algorithms=["HS256"]
        )
        return payload
    except JWTError:
        return None
