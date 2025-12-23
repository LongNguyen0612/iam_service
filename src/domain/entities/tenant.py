"""
Tenant Entity

Represents an isolated workspace for organizations.
"""

from datetime import datetime
from typing import Optional, TYPE_CHECKING
from uuid import UUID, uuid4

from sqlmodel import Column, DateTime, Field, Index, Relationship, SQLModel

from .enums import TenantStatus

if TYPE_CHECKING:
    from .membership import Membership


class Tenant(SQLModel, table=True):
    """
    Tenant entity - isolated workspace for organizations.

    Business Rules:
    - Each tenant has isolated data and billing
    - Soft delete: deleted_at marks deletion, async purge follows (UC-18)
    - Suspension blocks all operations (UC-17)
    """

    __tablename__ = "tenants"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    name: str = Field(max_length=255)

    status: TenantStatus = Field(default=TenantStatus.active)

    # Soft delete support (UC-18)
    deleted_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime))

    # Timestamps
    created_at: datetime = Field(
        default_factory=lambda: datetime.utcnow(), sa_column=Column(DateTime)
    )

    # Relationships
    memberships: list["Membership"] = Relationship(back_populates="tenant")

    __table_args__ = (
        Index("idx_tenant_status", "status"),
        Index("idx_tenant_deleted_at", "deleted_at"),
    )
