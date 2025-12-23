"""
Signup Use Case DTOs (Data Transfer Objects)

Command/Response pattern for clean architecture separation:
- SignupCommand: Input to use case (validated business intent)
- SignupResponse: Output from use case (structured result)
"""

from uuid import UUID
from pydantic import BaseModel


class SignupCommand(BaseModel):
    """
    Signup command - represents validated signup intent

    Created by API layer after request validation passes.
    Contains only business-relevant data (no HTTP concerns).
    """

    email: str
    password: str
    tenant_name: str


class UserInfo(BaseModel):
    """User information in signup response"""

    id: str
    email: str
    email_verified: bool


class TenantCreated(BaseModel):
    """Tenant information in signup response"""

    id: str
    name: str


class SignupResponse(BaseModel):
    """
    Signup response - structured output from use case

    Contains all data needed for API response.
    Decoupled from HTTP response format.
    """

    user: UserInfo
    tenant: TenantCreated
    access_token: str
    refresh_token: str
    session_id: str
