"""
Remove Member from Tenant Use Case

Handles removing (soft delete) members from a tenant.
"""

from uuid import UUID

from libs.result import Error, Result, Return
from src.app.services.unit_of_work import UnitOfWork
from src.domain.entities import MembershipRole, MembershipStatus

from .dtos import RemoveMemberResponse


class RemoveMemberUseCase:
    """
    Use case for removing members from a tenant.

    Business Rules (IAM-016):
    - AC-16.1: Successful removal - soft delete (status=revoked), revoke sessions, audit event
    - AC-16.2: Owner removes self (last owner) - fails with CANNOT_REMOVE_LAST_OWNER
    - AC-16.3: Owner removes self (multiple owners) - succeeds
    - AC-16.4: Admin removes owner - fails with INSUFFICIENT_ROLE
    - Only admin/owner can remove members
    """

    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    async def execute(
        self,
        requester_user_id: UUID,
        tenant_id: UUID,
        target_user_id: UUID,
    ) -> Result[RemoveMemberResponse]:
        """
        Execute remove member use case.

        Args:
            requester_user_id: User ID of the person removing the member
            tenant_id: Current tenant ID
            target_user_id: User ID of the member to remove

        Returns:
            Result with RemoveMemberResponse DTO, or Error
        """
        async with self.uow:
            # Get requester's membership to check role
            requester_membership = await self.uow.memberships.get_by_user_and_tenant(
                requester_user_id, tenant_id
            )

            if requester_membership is None:
                return Return.err(
                    Error("NOT_A_MEMBER", "You are not a member of this tenant")
                )

            # Verify requester has sufficient role (owner or admin)
            if requester_membership.role not in (
                MembershipRole.owner,
                MembershipRole.admin,
            ):
                return Return.err(
                    Error(
                        "INSUFFICIENT_ROLE",
                        "Only owners and admins can remove members",
                    )
                )

            # Get target membership
            target_membership = await self.uow.memberships.get_by_user_and_tenant(
                target_user_id, tenant_id
            )

            if target_membership is None:
                return Return.err(
                    Error(
                        "MEMBERSHIP_NOT_FOUND",
                        "Target user is not a member of this tenant",
                    )
                )

            # AC-16.4: Admin cannot remove owner
            if (
                requester_membership.role == MembershipRole.admin
                and target_membership.role == MembershipRole.owner
            ):
                return Return.err(
                    Error(
                        "INSUFFICIENT_ROLE",
                        "Admins cannot remove owners",
                    )
                )

            # Check if requester is trying to remove themselves and they're an owner
            is_self_removal = requester_user_id == target_user_id
            if is_self_removal and target_membership.role == MembershipRole.owner:
                # Count total owners in tenant
                all_memberships = await self.uow.memberships.get_by_tenant_id(tenant_id)
                owner_count = sum(
                    1
                    for m in all_memberships
                    if m.role == MembershipRole.owner
                    and m.status == MembershipStatus.active
                )

                # AC-16.2: Cannot remove last owner
                if owner_count == 1:
                    return Return.err(
                        Error(
                            "CANNOT_REMOVE_LAST_OWNER",
                            "Cannot remove the last owner of a tenant",
                        )
                    )
                # AC-16.3: Multiple owners - removal succeeds

            # AC-16.1: Soft delete - set status to revoked
            target_membership.status = MembershipStatus.revoked

            # Update membership
            await self.uow.memberships.update(target_membership)

            # AC-16.1: Revoke all sessions for this user in this tenant
            sessions = await self.uow.sessions.get_by_user_and_tenant(
                target_user_id, tenant_id
            )
            for session in sessions:
                session.revoked = True
                await self.uow.sessions.update(session)

            # AC-16.1: Create audit event
            from src.domain.entities import AuditEvent

            audit = AuditEvent(
                tenant_id=tenant_id,
                user_id=requester_user_id,
                action="member_removed",
                event_metadata={
                    "removed_user_id": str(target_user_id),
                    "removed_user_role": target_membership.role.value,
                },
            )
            await self.uow.audit_events.create(audit)

            # Commit transaction
            await self.uow.commit()

            # Return success response
            return Return.ok(RemoveMemberResponse(status="removed"))
