"""
Invitation Entity

Pending invitations to join a tenant.
"""

from datetime import datetime
from uuid import UUID, uuid4

from sqlmodel import Column, DateTime, Field, Index, SQLModel

from .enums import InvitationStatus, MembershipRole


class Invitation(SQLModel, table=True):
    """
    Invitation entity - pending invitations to join a tenant.

    Business Rules:
    - Created by admin/owner (UC-6)
    - Expires after 7 days
    - Token is single-use, cryptographically secure
    - Cannot invite existing members
    """

    __tablename__ = "invitations"

    id: UUID = Field(default_factory=uuid4, primary_key=True)

    tenant_id: UUID = Field(foreign_key="tenants.id", nullable=False, index=True)
    email: str = Field(max_length=255, nullable=False, index=True)

    role: MembershipRole = Field(nullable=False)
    token: str = Field(unique=True, index=True, max_length=64)  # SHA-256 hash

    status: InvitationStatus = Field(default=InvitationStatus.pending)

    # Timestamps
    expires_at: datetime = Field(sa_column=Column(DateTime))
    created_at: datetime = Field(
        default_factory=datetime.utcnow, sa_column=Column(DateTime)
    )

    __table_args__ = (
        Index("idx_invitation_expires_at", "expires_at"),
        Index("idx_invitation_tenant_email", "tenant_id", "email"),
        Index("idx_invitation_status", "status"),
    )
