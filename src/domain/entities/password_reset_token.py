"""
PasswordResetToken Entity

Secure password reset tokens.
"""

from datetime import datetime
from uuid import UUID, uuid4

from sqlmodel import Column, DateTime, Field, Index, SQLModel


class PasswordResetToken(SQLModel, table=True):
    """
    PasswordResetToken entity - secure password reset tokens.

    Business Rules:
    - Expires after 1 hour (UC-12, UC-13)
    - Token is SHA-256 hash of secure random string
    - Single-use: marked as used after confirmation
    - Rate limited: 3 requests per email per hour
    """

    __tablename__ = "password_reset_tokens"

    id: UUID = Field(default_factory=uuid4, primary_key=True)

    user_id: UUID = Field(foreign_key="users.id", index=True)
    token_hash: str = Field(max_length=64)  # SHA-256 output

    used: bool = Field(default=False)

    # Timestamps
    expires_at: datetime = Field(sa_column=Column(DateTime))
    created_at: datetime = Field(
        default_factory=datetime.utcnow, sa_column=Column(DateTime)
    )

    __table_args__ = (
        Index("idx_password_reset_expires_at", "expires_at"),
        Index("idx_password_reset_user_id", "user_id"),
        Index("idx_password_reset_used", "used"),
    )
