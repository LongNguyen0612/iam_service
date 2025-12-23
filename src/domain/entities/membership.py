"""
Membership Entity

Links User to Tenant with a role.
"""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlmodel import Column, DateTime, Field, Index, Relationship, SQLModel

from .enums import MembershipRole, MembershipStatus

if TYPE_CHECKING:
    from .user import User
    from .tenant import Tenant


class Membership(SQLModel, table=True):
    """
    Membership entity - links User to Tenant with a role.

    Business Rules:
    - One user can be member of multiple tenants
    - (user_id, tenant_id) must be unique
    - Revoked memberships block access
    - Only owners can change roles (UC-7)
    """

    __tablename__ = "memberships"

    id: UUID = Field(default_factory=uuid4, primary_key=True)

    user_id: UUID = Field(foreign_key="users.id", nullable=False, index=True)
    tenant_id: UUID = Field(foreign_key="tenants.id", nullable=False, index=True)

    role: MembershipRole = Field(nullable=False)
    status: MembershipStatus = Field(default=MembershipStatus.active)

    # Timestamps
    created_at: datetime = Field(
        default_factory=lambda: datetime.utcnow(), sa_column=Column(DateTime)
    )

    # Relationships
    user: "User" = Relationship(back_populates="memberships")
    tenant: "Tenant" = Relationship(back_populates="memberships")

    __table_args__ = (
        Index("idx_membership_user_tenant", "user_id", "tenant_id", unique=True),
        Index("idx_membership_status", "status"),
    )
