"""
List Tenant Invitations Use Case

Retrieves all invitations for a tenant.
"""

from uuid import UUID

from libs.result import Error, Result, Return
from src.app.services.unit_of_work import UnitOfWork

from .dtos import ListInvitationsResponse, InvitationDTO


class ListInvitationsUseCase:
    """
    Use case: List Tenant Invitations

    Retrieves all pending, accepted, and expired invitations for a tenant.
    Requires admin or owner role (enforced at API layer).
    """

    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    async def execute(
        self, tenant_id: UUID, requester_user_id: UUID
    ) -> Result[ListInvitationsResponse]:
        """
        Execute list invitations use case

        Args:
            tenant_id: The tenant to list invitations for
            requester_user_id: User requesting the list (for permission check)

        Returns:
            Result[ListInvitationsResponse]: List of invitations or error
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
                        message="Only admins and owners can list invitations",
                    )
                )

            # Get all invitations for this tenant
            invitations = await self.uow.invitations.get_by_tenant_id(tenant_id)

            # Get unique inviter user IDs
            inviter_ids = set(invitation.invited_by for invitation in invitations)

            # Fetch all inviters' information
            inviter_map = {}
            for inviter_id in inviter_ids:
                user = await self.uow.users.get_by_id(inviter_id)
                inviter_map[inviter_id] = user.email if user else "Unknown"

            # Convert to DTOs
            invitation_dtos = [
                InvitationDTO(
                    id=str(invitation.id),
                    email=invitation.email,
                    role=invitation.role.value,
                    status=invitation.status.value,
                    invited_by=str(invitation.invited_by),
                    invited_by_name=inviter_map.get(invitation.invited_by, "Unknown"),
                    created_at=invitation.created_at.isoformat(),
                    expires_at=invitation.expires_at.isoformat(),
                )
                for invitation in invitations
            ]

            return Return.ok(ListInvitationsResponse(invitations=invitation_dtos))
