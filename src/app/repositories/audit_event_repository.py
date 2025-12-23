from abc import ABC, abstractmethod
from typing import List, Optional, Tuple
from uuid import UUID

from src.domain.entities import AuditEvent


class IAuditEventRepository(ABC):
    """AuditEvent repository interface - application layer"""

    @abstractmethod
    async def create(self, audit_event: AuditEvent) -> AuditEvent:
        """Create a new audit event (immutable)"""
        pass

    @abstractmethod
    async def get_by_tenant_paginated(
        self, tenant_id: UUID, limit: int = 50, cursor: Optional[str] = None
    ) -> Tuple[List[AuditEvent], Optional[str]]:
        """
        Get audit events for a tenant with cursor-based pagination.

        Returns:
            Tuple of (events list, next_cursor)
            - events: List of audit events ordered by created_at DESC
            - next_cursor: Cursor for next page, None if no more events
        """
        pass
