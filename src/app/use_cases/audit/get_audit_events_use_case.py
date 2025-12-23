"""
Get Audit Events Use Case

Retrieves authentication audit events for a tenant with pagination.
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from libs.result import Error, Result, Return
from src.app.services.unit_of_work import UnitOfWork
from src.domain.entities import MembershipRole, MembershipStatus, TenantStatus


class GetAuditEventsUseCase:
    """
    Use case for retrieving audit events for a tenant.

    Business Rules:
    - Caller must have role=owner or role=admin (AC-9.2)
    - Results are tenant-scoped (only events for the tenant)
    - Results ordered by newest first
    - Supports cursor-based pagination
    - Each event includes action, user_email, timestamp, metadata
    """

    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    async def execute(
        self,
        user_id: UUID,
        tenant_id: UUID,
        role: str,
        limit: int = 50,
        cursor: Optional[str] = None,
    ) -> Result[Dict[str, Any]]:
        """
        Execute get audit events use case.

        Args:
            user_id: User UUID from JWT
            tenant_id: Tenant UUID from JWT
            role: Role from JWT (must be owner or admin)
            limit: Maximum number of events to return
            cursor: Pagination cursor (optional)

        Returns:
            Result with events list and next_cursor, or Error
        """
        async with self.uow:
            # AC-9.2: Check caller role (must be owner or admin)
            if role not in [MembershipRole.owner.value, MembershipRole.admin.value]:
                return Return.err(
                    Error(
                        "INSUFFICIENT_ROLE",
                        "You do not have permission to view audit events",
                    )
                )

            # Verify membership is still active
            membership = await self.uow.memberships.get_by_user_and_tenant(
                user_id, tenant_id
            )
            if membership is None or membership.status != MembershipStatus.active:
                return Return.err(
                    Error("MEMBERSHIP_REVOKED", "Membership has been revoked")
                )

            # Check tenant status
            tenant = await self.uow.tenants.get_by_id(tenant_id)
            if tenant is None:
                return Return.err(Error("TENANT_NOT_FOUND", "Tenant not found"))

            if tenant.status == TenantStatus.suspended:
                return Return.err(
                    Error("TENANT_SUSPENDED", "Tenant has been suspended")
                )

            # Get audit events with pagination
            events, next_cursor = await self.uow.audit_events.get_by_tenant_paginated(
                tenant_id, limit=limit, cursor=cursor
            )

            # Build events list with user email
            events_list = []
            for event in events:
                # Get user email if user_id is present
                user_email = None
                if event.user_id:
                    user = await self.uow.users.get_by_id(event.user_id)
                    if user:
                        user_email = user.email

                events_list.append(
                    {
                        "action": event.action,
                        "user_email": user_email,
                        "timestamp": event.created_at.isoformat() + "Z",
                        "metadata": event.event_metadata or {},
                    }
                )

            # Build response
            return Return.ok({"events": events_list, "next_cursor": next_cursor})
