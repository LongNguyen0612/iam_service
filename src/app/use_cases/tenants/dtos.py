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

    id: str  # Changed from invite_id to match InvitationDTO
    email: str
    role: str
    status: str
    invited_by: str
    invited_by_name: str  # Name of the user who sent the invitation
    created_at: str
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


class UserDTO(BaseModel):
    """DTO for user information within member response"""

    id: str
    name: str  # Using email as name for now
    email: str
    is_active: bool
    last_login_at: str | None


class MemberDTO(BaseModel):
    """DTO for a single tenant member"""

    user: UserDTO
    role: str
    status: str
    joined_at: str


class ListMembersResponse(BaseModel):
    """Response for list tenant members use case"""

    members: list[MemberDTO]


class InvitationDTO(BaseModel):
    """DTO for a single invitation"""

    id: str
    email: str
    role: str
    status: str
    invited_by: str
    invited_by_name: str  # Name of the user who sent the invitation
    created_at: str
    expires_at: str


class ListInvitationsResponse(BaseModel):
    """Response for list tenant invitations use case"""

    invitations: list[InvitationDTO]
