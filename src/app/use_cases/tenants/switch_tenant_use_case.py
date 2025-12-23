"""
Switch Active Tenant Use Case

Handles switching the user's active tenant context and issuing new JWT tokens.
"""

from datetime import UTC, datetime
from typing import Any, Dict
from uuid import UUID

from libs.result import Error, Result, Return
from src.app.services.unit_of_work import UnitOfWork
from src.domain.entities import MembershipStatus, TenantStatus
from src.api.utils.jwt import generate_jwt


class SwitchTenantUseCase:
    """
    Use case for switching active tenant and issuing new tenant-scoped JWT.

    Business Rules (IAM-005):
    - AC-5.1: User must be a member of the target tenant
    - AC-5.2: Membership must be active (not revoked)
    - AC-5.3: Tenant must be active (not suspended)
    - Updates user.last_active_tenant_id for future logins
    - Creates audit event for compliance tracking
    - Returns new JWT scoped to target tenant
    """

    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    async def execute(self, user_id: UUID, target_tenant_id: UUID) -> Result[Dict[str, Any]]:
        """
        Execute switch tenant use case.

        Args:
            user_id: Current authenticated user ID
            target_tenant_id: Target tenant ID to switch to

        Returns:
            Result with new access_token and tenant info, or Error
        """
        async with self.uow:
            # Get user
            user = await self.uow.users.get_by_id(user_id)
            if user is None:
                return Return.err(Error("USER_NOT_FOUND", "User not found"))

            # Get target tenant
            tenant = await self.uow.tenants.get_by_id(target_tenant_id)
            if tenant is None:
                return Return.err(Error("TENANT_NOT_FOUND", "Tenant not found"))

            # AC-5.4: Check if tenant is suspended
            if tenant.status == TenantStatus.suspended:
                return Return.err(
                    Error("TENANT_SUSPENDED", "Cannot switch to suspended tenant")
                )

            # Get all user memberships
            memberships = await self.uow.memberships.get_by_user_id(user_id)

            # Find membership for target tenant
            target_membership = None
            for membership in memberships:
                if membership.tenant_id == target_tenant_id:
                    target_membership = membership
                    break

            # AC-5.2: Check if user is a member of the target tenant
            if target_membership is None:
                return Return.err(
                    Error(
                        "NOT_A_MEMBER",
                        "User is not a member of the target tenant",
                    )
                )

            # AC-5.3: Check if membership is active (not revoked)
            if target_membership.status == MembershipStatus.revoked:
                return Return.err(
                    Error("MEMBERSHIP_REVOKED", "Membership has been revoked")
                )

            # Update user's last_active_tenant_id for future logins
            user.last_active_tenant_id = target_tenant_id
            await self.uow.users.update(user)

            # Create audit event for compliance
            from src.domain.entities import AuditEvent

            audit = AuditEvent(
                tenant_id=target_tenant_id,
                user_id=user_id,
                action="tenant_switch",
                event_metadata={
                    "previous_tenant_id": str(user.last_active_tenant_id)
                    if user.last_active_tenant_id != target_tenant_id
                    else None,
                    "new_tenant_id": str(target_tenant_id),
                    "tenant_name": tenant.name,
                },
            )
            await self.uow.audit_events.create(audit)

            # Commit transaction
            await self.uow.commit()

            # AC-5.1: Generate new JWT scoped to target tenant
            access_token = generate_jwt(
                user_id, target_tenant_id, target_membership.role.value
            )

            # Return success response
            return Return.ok(
                {
                    "access_token": access_token,
                    "tenant": {
                        "id": str(tenant.id),
                        "name": tenant.name,
                        "role": target_membership.role.value,
                    },
                }
            )
