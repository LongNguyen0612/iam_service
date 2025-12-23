"""
User Entity

Represents a person who can belong to multiple tenants.
"""

from datetime import datetime
from typing import Optional, TYPE_CHECKING
from uuid import UUID, uuid4

from sqlmodel import Column, DateTime, Field, Index, Relationship, SQLModel

from .enums import UserStatus

if TYPE_CHECKING:
    from .membership import Membership


class User(SQLModel, table=True):
    """
    User entity - represents a person who can belong to multiple tenants.

    Business Rules:
    - Email must be unique across all users
    - Email verification required for full access
    - Password stored as bcrypt hash (cost factor 12)
    - last_active_tenant_id determines default tenant on login
    """

    __tablename__ = "users"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    email: str = Field(unique=True, index=True, max_length=255)
    password_hash: str = Field(max_length=60)  # Bcrypt output is 60 chars

    status: UserStatus = Field(default=UserStatus.active)

    # Email verification (UC-10, UC-11)
    email_verified: bool = Field(default=False)
    email_verification_token: Optional[str] = Field(
        default=None, unique=True, index=True, max_length=64
    )
    email_verification_expires_at: Optional[datetime] = None

    # Default tenant for multi-tenant users (UC-2, UC-5)
    last_active_tenant_id: Optional[UUID] = Field(default=None, foreign_key="tenants.id")

    # Timestamps
    created_at: datetime = Field(
        default_factory=lambda: datetime.utcnow(), sa_column=Column(DateTime)
    )
    last_login_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime))

    # Relationships
    memberships: list["Membership"] = Relationship(back_populates="user")

    __table_args__ = (Index("idx_user_email_verified", "email_verified"),)
