"""
Change User Role Use Case

Handles changing a member's role within a tenant.
"""

from typing import Any, Dict
from uuid import UUID

from libs.result import Error, Result, Return
from src.app.services.unit_of_work import UnitOfWork
from src.domain.entities import MembershipRole


class ChangeRoleUseCase:
    """
    Use case for changing a member's role within a tenant.

    Business Rules (IAM-007):
    - AC-7.1: Only owner can change roles
    - AC-7.2: Owner cannot demote themselves
    - AC-7.3: Target user must be a member
    - AC-7.4: Validate role is valid
    - Updates Membership.role
    - Creates audit event for compliance tracking
    - User's existing JWT remains valid until expiry
    """

    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    async def execute(
        self, owner_user_id: UUID, tenant_id: UUID, target_user_id: UUID, new_role: str
    ) -> Result[Dict[str, Any]]:
        """
        Execute change role use case.

        Args:
            owner_user_id: User ID of the owner making the change
            tenant_id: Tenant ID
            target_user_id: User ID whose role is being changed
            new_role: New role to assign (owner/admin/member/viewer)

        Returns:
            Result with updated membership info, or Error
        """
        async with self.uow:
            # AC-7.4: Validate role is valid
            try:
                membership_role = MembershipRole(new_role)
            except ValueError:
                return Return.err(
                    Error(
                        "INVALID_ROLE",
                        f"Invalid role: {new_role}. Must be one of: owner, admin, member, viewer",
                    )
                )

            # Get owner's membership to verify they are the owner
            owner_membership = await self.uow.memberships.get_by_user_and_tenant(
                owner_user_id, tenant_id
            )

            if owner_membership is None:
                return Return.err(
                    Error("NOT_A_MEMBER", "You are not a member of this tenant")
                )

            # AC-7.1: Check if requester is the owner
            if owner_membership.role != MembershipRole.owner:
                return Return.err(
                    Error(
                        "INSUFFICIENT_ROLE",
                        "Only owners can change member roles",
                    )
                )

            # AC-7.3: Get target user's membership
            target_membership = await self.uow.memberships.get_by_user_and_tenant(
                target_user_id, tenant_id
            )

            if target_membership is None:
                return Return.err(
                    Error(
                        "MEMBERSHIP_NOT_FOUND",
                        "User is not a member of this tenant",
                    )
                )

            # AC-7.2: Prevent owner from demoting themselves
            if owner_user_id == target_user_id and owner_membership.role == MembershipRole.owner:
                if membership_role != MembershipRole.owner:
                    return Return.err(
                        Error(
                            "CANNOT_DEMOTE_SELF",
                            "Owner cannot demote themselves",
                        )
                    )

            # Store old role for audit
            old_role = target_membership.role.value

            # Update the role
            target_membership.role = membership_role
            await self.uow.memberships.update(target_membership)

            # Create audit event for compliance
            from src.domain.entities import AuditEvent

            audit = AuditEvent(
                tenant_id=tenant_id,
                user_id=owner_user_id,
                action="role_changed",
                event_metadata={
                    "target_user_id": str(target_user_id),
                    "old_role": old_role,
                    "new_role": new_role,
                },
            )
            await self.uow.audit_events.create(audit)

            # Commit transaction
            await self.uow.commit()

            # Return success response
            return Return.ok(
                {
                    "status": "updated",
                    "membership": {
                        "user_id": str(target_user_id),
                        "role": new_role,
                    },
                }
            )
