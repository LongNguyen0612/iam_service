"""
Load Context Use Case

Loads current user and tenant context from JWT claims.
"""

from typing import Any, Dict
from uuid import UUID

from libs.result import Error, Result, Return
from src.app.services.unit_of_work import UnitOfWork
from src.domain.entities import MembershipStatus, TenantStatus


class LoadContextUseCase:
    """
    Use case for loading current user and tenant context.

    Business Rules:
    - JWT payload provides user_id, tenant_id, role
    - User must exist
    - Tenant must exist and be active
    - Membership must exist and be active
    - Returns user details + tenant details + role
    """

    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    async def execute(
        self, user_id: UUID, tenant_id: UUID, role: str
    ) -> Result[Dict[str, Any]]:
        """
        Execute load context use case.

        Args:
            user_id: User UUID from JWT
            tenant_id: Tenant UUID from JWT
            role: Role from JWT (for verification)

        Returns:
            Result with user and tenant context, or Error
        """
        async with self.uow:
            # Load user
            user = await self.uow.users.get_by_id(user_id)
            if user is None:
                return Return.err(Error("USER_NOT_FOUND", "User not found"))

            # Load tenant
            tenant = await self.uow.tenants.get_by_id(tenant_id)
            if tenant is None:
                return Return.err(Error("TENANT_NOT_FOUND", "Tenant not found"))

            # Check tenant status
            if tenant.status == TenantStatus.suspended:
                return Return.err(
                    Error("TENANT_SUSPENDED", "Tenant has been suspended")
                )

            # Load membership
            membership = await self.uow.memberships.get_by_user_and_tenant(
                user_id, tenant_id
            )
            if membership is None:
                return Return.err(Error("MEMBERSHIP_NOT_FOUND", "Membership not found"))

            # Check membership status
            if membership.status != MembershipStatus.active:
                return Return.err(
                    Error("MEMBERSHIP_REVOKED", "Membership has been revoked")
                )

            # Build response
            return Return.ok(
                {
                    "user": {
                        "id": str(user.id),
                        "email": user.email,
                        "email_verified": user.email_verified,
                    },
                    "tenant": {
                        "id": str(tenant.id),
                        "name": tenant.name,
                        "role": membership.role.value,
                        "status": tenant.status.value,
                    },
                }
            )
