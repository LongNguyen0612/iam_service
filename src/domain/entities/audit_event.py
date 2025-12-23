"""
AuditEvent Entity

Immutable log of all authentication/authorization events.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

from sqlmodel import Column, DateTime, Field, Index, JSON, SQLModel


class AuditEvent(SQLModel, table=True):
    """
    AuditEvent entity - immutable log of all authentication/authorization events.

    Business Rules:
    - Immutable (never updated or deleted)
    - Retained for compliance (90 days minimum)
    - tenant_id nullable for global events (signup, etc.)
    - Metadata stores additional context (IP, user agent, etc.)
    """

    __tablename__ = "audit_events"

    id: UUID = Field(default_factory=uuid4, primary_key=True)

    tenant_id: Optional[UUID] = Field(default=None, index=True)
    user_id: Optional[UUID] = Field(default=None, index=True)

    action: str = Field(max_length=100)  # e.g., "login", "signup"
    event_metadata: Optional[dict] = Field(default=None, sa_column=Column(JSON))

    # Timestamps
    created_at: datetime = Field(
        default_factory=lambda: datetime.utcnow(), sa_column=Column(DateTime)
    )

    __table_args__ = (
        Index("idx_audit_created_at", "created_at"),
        Index("idx_audit_tenant_action", "tenant_id", "action"),
        Index("idx_audit_user_id", "user_id"),
    )
