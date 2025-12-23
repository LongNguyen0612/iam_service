"""
Use Case: Cancel Tenant Deletion (IAM-018, AC-18.3)

Allows canceling tenant deletion within 7-day rollback window.
Admin-only endpoint for support/recovery purposes.
"""

from datetime import datetime, UTC, timedelta
from uuid import UUID
from pydantic import BaseModel

from libs.result import Error, Result, Return
from src.app.services.unit_of_work import UnitOfWork
from src.domain.entities.enums import TenantStatus


class CancelTenantDeletionResponse(BaseModel):
    """Response DTO for CancelTenantDeletionUseCase"""

    status: str
    tenant_name: str
    restored_at: str


class CancelTenantDeletionUseCase:
    """
    Cancel tenant deletion within 7-day rollback window.

    Business Logic:
    1. Validate tenant exists and is marked for deletion
    2. Check that deletion is within 7-day rollback window
    3. Restore tenant status to active
    4. Clear deleted_at timestamp
    5. Create audit event
    6. Return confirmation

    Note: This is an admin/support endpoint, not accessible to regular users.
    Sessions are NOT automatically restored - users must log in again.
    """

    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    async def execute(self, tenant_id: UUID) -> Result[CancelTenantDeletionResponse]:
        """
        Execute cancel tenant deletion use case.

        Args:
            tenant_id: UUID of tenant to restore

        Returns:
            Result[CancelTenantDeletionResponse] with restoration details

        Errors:
            - TENANT_NOT_FOUND: Tenant does not exist
            - NOT_SCHEDULED_FOR_DELETION: Tenant is not marked for deletion
            - ROLLBACK_WINDOW_EXPIRED: More than 7 days since deletion
        """
        async with self.uow:
            # 1. Get tenant
            tenant = await self.uow.tenants.get_by_id(tenant_id)
            if not tenant:
                return Return.err(Error("TENANT_NOT_FOUND", "Tenant not found"))

            # 2. Check if tenant is marked for deletion
            if tenant.deleted_at is None:
                return Return.err(
                    Error(
                        "NOT_SCHEDULED_FOR_DELETION",
                        "Tenant is not scheduled for deletion",
                    )
                )

            # 3. Check if within 7-day rollback window
            now = datetime.now(UTC)
            # Ensure deleted_at is timezone-aware for comparison
            deleted_at_aware = (
                tenant.deleted_at.replace(tzinfo=UTC)
                if tenant.deleted_at.tzinfo is None
                else tenant.deleted_at
            )
            rollback_deadline = deleted_at_aware + timedelta(days=7)
            if now > rollback_deadline:
                return Return.err(
                    Error(
                        "ROLLBACK_WINDOW_EXPIRED",
                        "Rollback window has expired (7 days from deletion)",
                        reason=f"Deleted at {tenant.deleted_at.isoformat()}, deadline was {rollback_deadline.isoformat()}",
                    )
                )

            # 4. Restore tenant
            tenant_name = tenant.name
            tenant.status = TenantStatus.active
            tenant.deleted_at = None
            await self.uow.tenants.update(tenant)

            # 5. Create audit event
            from src.domain.entities import AuditEvent

            audit_event = AuditEvent(
                tenant_id=tenant_id,
                user_id=None,  # Admin action, no specific user
                action="tenant_deletion_cancelled",
                event_metadata={
                    "tenant_name": tenant_name,
                    "restored_at": now.isoformat(),
                    "original_deletion_date": deleted_at_aware.isoformat()
                    if deleted_at_aware
                    else None,
                },
            )
            await self.uow.audit_events.create(audit_event)

            # 6. Commit transaction
            await self.uow.commit()

            return Return.ok(
                CancelTenantDeletionResponse(
                    status="restored",
                    tenant_name=tenant_name,
                    restored_at=now.isoformat(),
                )
            )
