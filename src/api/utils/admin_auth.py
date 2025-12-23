"""
Admin API Key Authentication

Validates admin API keys for system administration endpoints.
"""

from fastapi import Header, status
from libs.result import Error
from src.api.error import ClientError
from config import ApplicationConfig


async def verify_admin_api_key(x_admin_api_key: str = Header(None)):
    """
    Verify admin API key from X-Admin-API-Key header.

    This is used for billing system and other internal service integrations.
    Different from user JWT authentication - this is service-to-service auth.

    Args:
        x_admin_api_key: API key from X-Admin-API-Key header

    Raises:
        ClientError: 401 if key is missing or invalid

    Returns:
        True if valid
    """
    if not x_admin_api_key:
        raise ClientError(
            Error("UNAUTHORIZED", "Admin API key required"),
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    # Get admin API key from config
    # In production, this should be stored securely (e.g., environment variable, secrets manager)
    valid_admin_key = getattr(ApplicationConfig, "ADMIN_API_KEY", "test-admin-key-12345")

    if x_admin_api_key != valid_admin_key:
        raise ClientError(
            Error("INVALID_API_KEY", "Invalid admin API key"),
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    return True
