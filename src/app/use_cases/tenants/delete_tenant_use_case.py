"""
Use Case: Delete Tenant (IAM-018, AC-18.1)

Initiates soft delete of a tenant with 7-day rollback window.
Only owner can delete tenant. Requires explicit confirmation string.
"""

from datetime import datetime, UTC
from uuid import UUID
from pydantic import BaseModel

from libs.result import Error, Result, Return
from src.app.services.unit_of_work import UnitOfWork
from src.domain.entities.enums import TenantStatus, MembershipRole


class DeleteTenantResponse(BaseModel):
    """Response DTO for DeleteTenantUseCase"""

    status: str
    purge_scheduled_at: str
    rollback_deadline: str
    sessions_revoked: int


class DeleteTenantUseCase:
    """
    Initiate tenant soft deletion (owner only, requires confirmation).

    Business Logic:
    1. Validate user is owner of the tenant
    2. Validate confirmation string matches pattern
    3. Check for unpaid balance (future: integrate with billing service)
    4. Set tenant status to suspended
    5. Set tenant deleted_at timestamp
    6. Revoke all active sessions for all users in tenant
    7. Create audit event
    8. Return deletion details with 7-day rollback deadline

    Future Enhancement:
    - Queue background purge job (Celery/RabbitMQ)
    - Integration with billing service for balance check
    - Terminate agent executions (when agent service exists)
    """

    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    async def execute(
        self,
        user_id: UUID,
        tenant_id: UUID,
        confirmation: str,
    ) -> Result[DeleteTenantResponse]:
        """
        Execute delete tenant use case.

        Args:
            user_id: UUID of user initiating deletion
            tenant_id: UUID of tenant to delete
            confirmation: Confirmation string (must match "DELETE_TENANT_{tenant_name}")

        Returns:
            Result[DeleteTenantResponse] with deletion details

        Errors:
            - TENANT_NOT_FOUND: Tenant does not exist
            - INSUFFICIENT_ROLE: User is not owner
            - INVALID_CONFIRMATION: Confirmation string doesn't match
            - ALREADY_DELETED: Tenant already marked for deletion
            - PAYMENT_REQUIRED: Unpaid balance exists (future)
        """
        async with self.uow:
            # 1. Get tenant
            tenant = await self.uow.tenants.get_by_id(tenant_id)
            if not tenant:
                return Return.err(Error("TENANT_NOT_FOUND", "Tenant not found"))

            # 2. Verify user is owner
            membership = await self.uow.memberships.get_by_user_and_tenant(
                user_id, tenant_id
            )
            if not membership or membership.role != MembershipRole.owner:
                return Return.err(
                    Error(
                        "INSUFFICIENT_ROLE",
                        "Only tenant owner can delete the tenant",
                    )
                )

            # 3. Check if already deleted
            if tenant.deleted_at is not None:
                return Return.err(
                    Error(
                        "ALREADY_DELETED",
                        "Tenant is already scheduled for deletion",
                    )
                )

            # 4. Validate confirmation string
            expected_confirmation = f"DELETE_TENANT_{tenant.name.replace(' ', '_')}"
            if confirmation != expected_confirmation:
                return Return.err(
                    Error(
                        "INVALID_CONFIRMATION",
                        f"Confirmation string must be: {expected_confirmation}",
                        reason=f"Expected '{expected_confirmation}' but got '{confirmation}'",
                    )
                )

            # 5. Check for unpaid balance (future: billing service integration)
            # For now, we skip this check. In production:
            # balance = await billing_service.get_tenant_balance(tenant_id)
            # if balance > 0:
            #     return Return.err(Error("PAYMENT_REQUIRED", "Cannot delete tenant with unpaid balance"))

            # 6. Mark tenant for deletion
            now = datetime.now(UTC)
            tenant.status = TenantStatus.suspended
            tenant.deleted_at = now
            await self.uow.tenants.update(tenant)

            # 7. Revoke all active sessions for all users in this tenant
            sessions = await self.uow.sessions.get_active_by_tenant_id(tenant_id)
            sessions_revoked = 0
            for session in sessions:
                if not session.revoked:
                    session.revoked = True
                    session.revoked_at = now
                    await self.uow.sessions.update(session)
                    sessions_revoked += 1

            # 8. Create audit event
            from src.domain.entities import AuditEvent

            audit_event = AuditEvent(
                tenant_id=tenant_id,
                user_id=user_id,
                action="tenant_deletion_initiated",
                event_metadata={
                    "tenant_name": tenant.name,
                    "sessions_revoked": sessions_revoked,
                    "deleted_at": now.isoformat(),
                    "confirmation": confirmation,
                },
            )
            await self.uow.audit_events.create(audit_event)

            # 9. Commit transaction
            await self.uow.commit()

            # Calculate purge schedule (7 days from now)
            from datetime import timedelta

            purge_date = now + timedelta(days=7)

            return Return.ok(
                DeleteTenantResponse(
                    status="deletion_initiated",
                    purge_scheduled_at=purge_date.isoformat(),
                    rollback_deadline=purge_date.isoformat(),
                    sessions_revoked=sessions_revoked,
                )
            )
