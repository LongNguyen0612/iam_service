"""
Audit Service Interface

Service interface for audit event logging using MongoDB.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID


class IAuditService(ABC):
    """Abstract interface for audit event logging and retrieval"""

    @abstractmethod
    async def log_event(
        self,
        action: str,
        tenant_id: Optional[UUID],
        user_id: Optional[UUID],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log an audit event.

        Args:
            action: Type of event (e.g., "login", "signup", "member_removed")
            tenant_id: Tenant UUID (optional for global events like signup)
            user_id: User UUID who triggered the event
            metadata: Additional event context (IP, user agent, email, etc.)
        """
        pass

    @abstractmethod
    async def get_by_tenant_paginated(
        self,
        tenant_id: UUID,
        limit: int = 50,
        cursor: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """
        Get audit events for a tenant with cursor-based pagination.

        Args:
            tenant_id: Tenant UUID to filter events
            limit: Maximum number of events to return
            cursor: Pagination cursor (optional)

        Returns:
            Tuple of (events list, next_cursor)
            - events: List of audit event dicts ordered by created_at DESC
            - next_cursor: Cursor for next page, None if no more events
        """
        pass
