import base64
from datetime import datetime
from typing import List, Optional, Tuple
from uuid import UUID

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from src.app.repositories.audit_event_repository import IAuditEventRepository
from src.domain.entities import AuditEvent


class AuditEventRepository(IAuditEventRepository):
    """AuditEvent repository implementation using SQLModel"""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, audit_event: AuditEvent) -> AuditEvent:
        """Create a new audit event (immutable)"""
        self.session.add(audit_event)
        await self.session.flush()
        await self.session.refresh(audit_event)
        return audit_event

    async def get_by_tenant_paginated(
        self, tenant_id: UUID, limit: int = 50, cursor: Optional[str] = None
    ) -> Tuple[List[AuditEvent], Optional[str]]:
        """
        Get audit events for a tenant with cursor-based pagination.

        Cursor format: base64-encoded ISO timestamp of created_at
        """
        # Build query
        stmt = select(AuditEvent).where(AuditEvent.tenant_id == tenant_id)

        # Apply cursor if provided
        if cursor:
            try:
                # Decode cursor (base64-encoded ISO timestamp)
                cursor_timestamp_str = base64.b64decode(cursor).decode("utf-8")
                cursor_timestamp = datetime.fromisoformat(cursor_timestamp_str)
                stmt = stmt.where(AuditEvent.created_at < cursor_timestamp)
            except (ValueError, TypeError):
                # Invalid cursor, ignore and return from beginning
                pass

        # Order by created_at DESC (newest first) and apply limit
        stmt = stmt.order_by(AuditEvent.created_at.desc()).limit(limit + 1)

        # Execute query
        result = await self.session.exec(stmt)
        events = list(result.all())

        # Determine if there are more events
        has_more = len(events) > limit
        if has_more:
            events = events[:limit]

        # Generate next cursor if there are more events
        next_cursor = None
        if has_more and events:
            last_event = events[-1]
            # Encode the created_at timestamp as cursor
            cursor_timestamp_str = last_event.created_at.isoformat()
            next_cursor = base64.b64encode(cursor_timestamp_str.encode("utf-8")).decode("utf-8")

        return events, next_cursor
