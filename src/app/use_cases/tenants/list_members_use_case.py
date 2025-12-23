"""
List Tenant Members Use Case

Retrieves all members of a tenant with their roles and status.
"""

from uuid import UUID

from libs.result import Error, Result, Return
from src.app.services.unit_of_work import UnitOfWork

from .dtos import ListMembersResponse, MemberDTO, UserDTO


class ListMembersUseCase:
    """
    Use case: List Tenant Members

    Retrieves all active and revoked members of a tenant.
    Requires admin or owner role (enforced at API layer).
    """

    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    async def execute(self, tenant_id: UUID, requester_user_id: UUID) -> Result[ListMembersResponse]:
        """
        Execute list members use case

        Args:
            tenant_id: The tenant to list members for
            requester_user_id: User requesting the list (for permission check)

        Returns:
            Result[ListMembersResponse]: List of members or error
        """
        async with self.uow:
            # Verify requester is a member of this tenant
            requester_membership = await self.uow.memberships.get_by_user_and_tenant(
                requester_user_id, tenant_id
            )

            if not requester_membership:
                return Return.err(
                    Error(code="NOT_A_MEMBER", message="You are not a member of this tenant")
                )

            # Verify requester has admin or owner role
            if requester_membership.role.value not in ["admin", "owner"]:
                return Return.err(
                    Error(
                        code="INSUFFICIENT_ROLE",
                        message="Only admins and owners can list members",
                    )
                )

            # Get all memberships for this tenant
            memberships = await self.uow.memberships.get_by_tenant_id(tenant_id)

            # Convert to DTOs
            member_dtos = []
            for membership in memberships:
                # Get user info (membership has relationship to user)
                user = membership.user
                member_dtos.append(
                    MemberDTO(
                        user=UserDTO(
                            id=str(user.id),
                            name=user.email,  # Using email as name since User doesn't have name field
                            email=user.email,
                            is_active=user.status.value == "active",
                            last_login_at=user.last_login_at.isoformat() if user.last_login_at else None,
                        ),
                        role=membership.role.value,
                        status=membership.status.value,
                        joined_at=membership.created_at.isoformat(),
                    )
                )

            return Return.ok(ListMembersResponse(members=member_dtos))
