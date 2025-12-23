"""
Authentication Use Case DTOs (Data Transfer Objects)

All Command and Response classes for auth domain.
Provides type safety and clear contracts between layers.
"""

from typing import List
from pydantic import BaseModel


# ============================================================================
# Response DTOs
# ============================================================================


class VerifyEmailResponse(BaseModel):
    """Response for email verification use case"""

    status: str
    message: str


class ResendVerificationResponse(BaseModel):
    """Response for resend verification email use case"""

    status: str
    message: str


class TenantInfo(BaseModel):
    """Tenant information in authentication responses"""

    id: str
    name: str
    role: str


class LoginResponse(BaseModel):
    """Response for user login use case"""

    access_token: str
    refresh_token: str
    session_id: str
    active_tenant: TenantInfo
    other_tenants: List[TenantInfo]


class RefreshTokenResponse(BaseModel):
    """Response for refresh token use case"""

    access_token: str
    refresh_token: str
    session_id: str


class RequestPasswordResetResponse(BaseModel):
    """Response for request password reset use case"""

    status: str
    message: str


class ConfirmPasswordResetResponse(BaseModel):
    """Response for confirm password reset use case"""

    status: str
    message: str
