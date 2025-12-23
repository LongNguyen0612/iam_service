"""
Use Case: Restore Tenant (IAM-017, AC-17.2)

Billing integration endpoint to restore a suspended tenant after payment.
Allows users to log in and access tenant resources again.
"""

from datetime import datetime, UTC
from uuid import UUID
from pydantic import BaseModel

from libs.result import Error, Result, Return
from src.app.services.audit_service import IAuditService
from src.app.services.unit_of_work import UnitOfWork
from src.domain.entities.enums import TenantStatus


class RestoreTenantResponse(BaseModel):
    """Response DTO for RestoreTenantUseCase"""

    status: str


class RestoreTenantUseCase:
    """
    Restore a suspended tenant after payment received.

    Business Logic:
    1. Validate tenant exists
    2. Update tenant status to active
    3. Create audit event
    4. Users can now log in and create new sessions

    Idempotent: Restoring already-active tenant succeeds
    """

    def __init__(self, uow: UnitOfWork, audit_service: IAuditService):
        self.uow = uow
        self.audit_service = audit_service

    async def execute(self, tenant_id: UUID) -> Result[RestoreTenantResponse]:
        """
        Execute restore tenant use case.

        Args:
            tenant_id: UUID of tenant to restore

        Returns:
            Result[RestoreTenantResponse] with status
        """
        async with self.uow:
            # 1. Get tenant
            tenant = await self.uow.tenants.get_by_id(tenant_id)
            if not tenant:
                return Return.err(
                    Error("TENANT_NOT_FOUND", "Tenant not found")
                )

            # 2. Update tenant status to active
            tenant.status = TenantStatus.active
            await self.uow.tenants.update(tenant)

            # 3. Commit transaction
            await self.uow.commit()

            # 4. Create audit event (best effort, after commit)
            await self.audit_service.log_event(
                action="tenant_restored",
                tenant_id=tenant_id,
                user_id=None,  # System action, no specific user
                metadata={
                    "restored_at": datetime.now(UTC).isoformat(),
                },
            )

            return Return.ok(
                RestoreTenantResponse(
                    status="active",
                )
            )
