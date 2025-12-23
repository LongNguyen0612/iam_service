"""
Revoke Invitation Use Case

Handles revoking pending invitations.
"""

from uuid import UUID

from libs.result import Error, Result, Return
from src.app.services.unit_of_work import UnitOfWork
from src.domain.entities import InvitationStatus, MembershipRole

from .dtos import RevokeInvitationResponse


class RevokeInvitationUseCase:
    """
    Use case for revoking pending invitations.

    Business Rules (IAM-015):
    - AC-15.2: Revoke invitation - updates status to expired, creates audit event
    - AC-15.3: Already accepted - fails with 409 Conflict
    - Only admin/owner can revoke
    """

    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    async def execute(
        self, user_id: UUID, tenant_id: UUID, invitation_id: UUID
    ) -> Result[RevokeInvitationResponse]:
        """
        Execute revoke invitation use case.

        Args:
            user_id: User ID of the person revoking the invite
            tenant_id: Current tenant ID
            invitation_id: ID of the invitation to revoke

        Returns:
            Result with RevokeInvitationResponse DTO, or Error
        """
        async with self.uow:
            # Check user's membership to verify they're admin/owner
            membership = await self.uow.memberships.get_by_user_and_tenant(
                user_id, tenant_id
            )

            if membership is None:
                return Return.err(
                    Error("NOT_A_MEMBER", "You are not a member of this tenant")
                )

            # Verify user has sufficient role (owner or admin)
            if membership.role not in (MembershipRole.owner, MembershipRole.admin):
                return Return.err(
                    Error(
                        "INSUFFICIENT_ROLE",
                        "Only owners and admins can revoke invitations",
                    )
                )

            # Get the invitation
            invitation = await self.uow.invitations.get_by_id(invitation_id)

            if invitation is None:
                return Return.err(
                    Error("INVITATION_NOT_FOUND", "Invitation not found")
                )

            # Verify invitation belongs to this tenant
            if invitation.tenant_id != tenant_id:
                return Return.err(
                    Error("INVITATION_NOT_FOUND", "Invitation not found")
                )

            # AC-15.3: Check if already accepted
            if invitation.status == InvitationStatus.accepted:
                return Return.err(
                    Error(
                        "INVITATION_ALREADY_ACCEPTED",
                        "Cannot revoke an invitation that has already been accepted",
                    )
                )

            # AC-15.2: Update status to expired
            invitation.status = InvitationStatus.expired

            # Update invitation
            await self.uow.invitations.update(invitation)

            # AC-15.2: Create audit event
            from src.domain.entities import AuditEvent

            audit = AuditEvent(
                tenant_id=tenant_id,
                user_id=user_id,
                action="invitation_revoked",
                event_metadata={
                    "invitation_id": str(invitation.id),
                    "email": invitation.email,
                },
            )
            await self.uow.audit_events.create(audit)

            # Commit transaction
            await self.uow.commit()

            # Return success response
            return Return.ok(RevokeInvitationResponse(status="revoked"))
