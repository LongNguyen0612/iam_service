"""
Use Case: Suspend Tenant (IAM-017, AC-17.1)

Billing integration endpoint to suspend a tenant for non-payment.
Revokes all active sessions and blocks tenant operations.
"""

from datetime import datetime, UTC
from uuid import UUID
from pydantic import BaseModel

from libs.result import Error, Result, Return
from src.app.services.audit_service import IAuditService
from src.app.services.unit_of_work import UnitOfWork
from src.domain.entities.enums import TenantStatus


class SuspendTenantResponse(BaseModel):
    """Response DTO for SuspendTenantUseCase"""

    status: str
    sessions_revoked: int


class SuspendTenantUseCase:
    """
    Suspend a tenant for non-payment (billing integration).

    Business Logic:
    1. Validate tenant exists
    2. Update tenant status to suspended
    3. Revoke all active sessions for users in this tenant
    4. Create audit event
    5. Return number of sessions revoked

    Idempotent: Suspending already-suspended tenant succeeds but revokes 0 sessions
    """

    def __init__(self, uow: UnitOfWork, audit_service: IAuditService):
        self.uow = uow
        self.audit_service = audit_service

    async def execute(self, tenant_id: UUID) -> Result[SuspendTenantResponse]:
        """
        Execute suspend tenant use case.

        Args:
            tenant_id: UUID of tenant to suspend

        Returns:
            Result[SuspendTenantResponse] with status and sessions_revoked count
        """
        async with self.uow:
            # 1. Get tenant
            tenant = await self.uow.tenants.get_by_id(tenant_id)
            if not tenant:
                return Return.err(
                    Error("TENANT_NOT_FOUND", "Tenant not found")
                )

            # 2. Update tenant status to suspended
            tenant.status = TenantStatus.suspended
            await self.uow.tenants.update(tenant)

            # 3. Revoke all active sessions for this tenant
            sessions = await self.uow.sessions.get_active_by_tenant_id(tenant_id)
            sessions_revoked = 0
            for session in sessions:
                if not session.revoked:
                    session.revoked = True
                    session.revoked_at = datetime.now(UTC)
                    await self.uow.sessions.update(session)
                    sessions_revoked += 1

            # 4. Commit transaction
            await self.uow.commit()

            # 5. Create audit event (best effort, after commit)
            await self.audit_service.log_event(
                action="tenant_suspended",
                tenant_id=tenant_id,
                user_id=None,  # System action, no specific user
                metadata={
                    "sessions_revoked": sessions_revoked,
                    "suspended_at": datetime.now(UTC).isoformat(),
                },
            )

            return Return.ok(
                SuspendTenantResponse(
                    status="suspended",
                    sessions_revoked=sessions_revoked,
                )
            )
