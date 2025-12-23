"""
Tenant Use Case DTOs (Data Transfer Objects)

All Command and Response classes for tenant domain.
Provides type safety and clear contracts between layers.
"""

from pydantic import BaseModel


# ============================================================================
# Response DTOs
# ============================================================================


class InviteUserResponse(BaseModel):
    """Response for invite user to tenant use case"""

    invite_id: str
    status: str
    expires_at: str


class TenantInfo(BaseModel):
    """Tenant information in invitation acceptance response"""

    id: str
    name: str
    role: str


class AcceptInvitationResponse(BaseModel):
    """Response for accept invitation use case"""

    access_token: str
    refresh_token: str
    tenant: TenantInfo
    email_verification_required: bool


class ResendInvitationResponse(BaseModel):
    """Response for resend invitation use case"""

    status: str
    expires_at: str


class RevokeInvitationResponse(BaseModel):
    """Response for revoke invitation use case"""

    status: str


class RemoveMemberResponse(BaseModel):
    """Response for remove member use case"""

    status: str
