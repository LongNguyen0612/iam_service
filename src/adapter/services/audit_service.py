"""
MongoDB Audit Service Implementation

Implements audit event logging and retrieval using MongoDB.
"""

import base64
from datetime import UTC, datetime
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

from motor.motor_asyncio import AsyncIOMotorClient

from src.app.services.audit_service import IAuditService


class MongoAuditService(IAuditService):
    """MongoDB implementation of IAuditService"""

    def __init__(self, mongo_client: AsyncIOMotorClient, db_name: str):
        self.client = mongo_client
        self.db = self.client[db_name]
        self.collection = self.db["audit_events"]

    async def log_event(
        self,
        action: str,
        tenant_id: Optional[UUID],
        user_id: Optional[UUID],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log an audit event to MongoDB"""
        event = {
            "_id": str(uuid4()),
            "action": action,
            "tenant_id": str(tenant_id) if tenant_id else None,
            "user_id": str(user_id) if user_id else None,
            "event_metadata": metadata or {},
            "created_at": datetime.now(UTC),
        }
        await self.collection.insert_one(event)

    async def get_by_tenant_paginated(
        self,
        tenant_id: UUID,
        limit: int = 50,
        cursor: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """
        Get audit events for a tenant with cursor-based pagination.

        Cursor format: base64-encoded ISO timestamp of created_at
        """
        # Build query
        query = {"tenant_id": str(tenant_id)}

        # Apply cursor if provided
        if cursor:
            try:
                cursor_timestamp_str = base64.b64decode(cursor).decode("utf-8")
                cursor_timestamp = datetime.fromisoformat(cursor_timestamp_str)
                query["created_at"] = {"$lt": cursor_timestamp}
            except (ValueError, TypeError):
                # Invalid cursor, ignore and return from beginning
                pass

        # Execute query with sort and limit
        cursor_result = self.collection.find(query).sort("created_at", -1).limit(limit + 1)
        events = await cursor_result.to_list(length=limit + 1)

        # Determine if there are more events
        has_more = len(events) > limit
        if has_more:
            events = events[:limit]

        # Generate next cursor if there are more events
        next_cursor = None
        if has_more and events:
            last_event = events[-1]
            cursor_timestamp_str = last_event["created_at"].isoformat()
            next_cursor = base64.b64encode(cursor_timestamp_str.encode("utf-8")).decode("utf-8")

        # Convert MongoDB documents to dicts with proper format
        result_events = []
        for event in events:
            result_events.append({
                "id": event["_id"],
                "action": event["action"],
                "tenant_id": event.get("tenant_id"),
                "user_id": event.get("user_id"),
                "event_metadata": event.get("event_metadata", {}),
                "created_at": event["created_at"],
            })

        return result_events, next_cursor
