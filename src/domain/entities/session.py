"""
Session Entity

Stores refresh tokens for authentication.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

from sqlmodel import Column, DateTime, Field, Index, SQLModel


class Session(SQLModel, table=True):
    """
    Session entity - stores refresh tokens for authentication.

    Business Rules:
    - Refresh tokens are hashed (bcrypt)
    - Tokens rotate on each refresh (UC-3)
    - Revoked sessions block token refresh
    - Expires after 30 days
    """

    __tablename__ = "sessions"

    id: UUID = Field(default_factory=uuid4, primary_key=True)

    user_id: UUID = Field(foreign_key="users.id", nullable=False, index=True)
    tenant_id: UUID = Field(foreign_key="tenants.id", nullable=False, index=True)

    refresh_token_hash: str = Field(max_length=60)  # Bcrypt output
    revoked: bool = Field(default=False)
    revoked_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime))

    # Timestamps
    created_at: datetime = Field(
        default_factory=lambda: datetime.utcnow(), sa_column=Column(DateTime)
    )
    expires_at: datetime = Field(sa_column=Column(DateTime))

    __table_args__ = (
        Index("idx_session_expires_at", "expires_at"),
        Index("idx_session_user_tenant", "user_id", "tenant_id"),
        Index("idx_session_revoked", "revoked"),
    )
