"""
Invite User to Tenant Use Case

Handles inviting users to join a tenant with specified roles.
"""

import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

from libs.result import Error, Result, Return
from src.app.services.unit_of_work import UnitOfWork
from src.domain.entities import Invitation, MembershipRole

from .dtos import InviteUserResponse


class InviteUserUseCase:
    """
    Use case for inviting users to join a tenant.

    Business Rules (IAM-006):
    - AC-6.1: Only owner/admin can invite users
    - AC-6.2: Validate role is a valid MembershipRole
    - AC-6.3: Prevent duplicate pending invitations
    - AC-6.4: Prevent inviting existing members
    - Creates invitation with 7-day expiration
    - Generates cryptographically secure token (32 characters)
    - Creates audit event for compliance tracking
    """

    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    async def execute(
        self, inviter_user_id: UUID, tenant_id: UUID, email: str, role: str
    ) -> Result[InviteUserResponse]:
        """
        Execute invite user use case.

        Args:
            inviter_user_id: User ID of the person sending the invite
            tenant_id: Target tenant ID
            email: Email address to invite
            role: Role to assign (owner/admin/member/viewer)

        Returns:
            Result with InviteUserResponse DTO, or Error
        """
        async with self.uow:
            # AC-6.5: Validate role is valid
            try:
                membership_role = MembershipRole(role)
            except ValueError:
                return Return.err(
                    Error(
                        "INVALID_ROLE",
                        f"Invalid role: {role}. Must be one of: owner, admin, member, viewer",
                    )
                )

            # Get inviter's membership to check role
            inviter_membership = await self.uow.memberships.get_by_user_and_tenant(
                inviter_user_id, tenant_id
            )

            if inviter_membership is None:
                return Return.err(
                    Error("NOT_A_MEMBER", "You are not a member of this tenant")
                )

            # AC-6.2: Check if inviter has sufficient role (owner or admin)
            if inviter_membership.role not in (
                MembershipRole.owner,
                MembershipRole.admin,
            ):
                return Return.err(
                    Error(
                        "INSUFFICIENT_ROLE",
                        "Only owners and admins can invite users",
                    )
                )

            # AC-6.4: Check if user with this email is already a member
            # First, get the user by email
            existing_user = await self.uow.users.get_by_email(email)
            if existing_user:
                # Check if they already have a membership
                existing_membership = await self.uow.memberships.get_by_user_and_tenant(
                    existing_user.id, tenant_id
                )
                if existing_membership:
                    return Return.err(
                        Error("ALREADY_MEMBER", "User is already a member of this tenant")
                    )

            # AC-6.3: Check for duplicate pending invitation
            pending_invitation = await self.uow.invitations.get_pending_by_tenant_and_email(
                tenant_id, email
            )
            if pending_invitation:
                return Return.err(
                    Error(
                        "INVITE_ALREADY_EXISTS",
                        "A pending invitation already exists for this email",
                    )
                )

            # Generate cryptographically secure token (32 characters)
            token = secrets.token_urlsafe(32)

            # Create invitation with 7-day expiration
            invitation = Invitation(
                tenant_id=tenant_id,
                email=email,
                role=membership_role,
                token=token,
                expires_at=datetime.now(UTC) + timedelta(days=7),
            )

            await self.uow.invitations.create(invitation)

            # Create audit event for compliance
            from src.domain.entities import AuditEvent

            audit = AuditEvent(
                tenant_id=tenant_id,
                user_id=inviter_user_id,
                action="invite_sent",
                event_metadata={
                    "invitation_id": str(invitation.id),
                    "invited_email": email,
                    "role": role,
                },
            )
            await self.uow.audit_events.create(audit)

            # Commit transaction
            await self.uow.commit()

            # TODO: Send invitation email asynchronously
            # This would typically push a message to a queue (RabbitMQ, etc.)
            # For now, we'll just log that the email should be sent

            # Return success response with Pydantic DTO
            return Return.ok(
                InviteUserResponse(
                    invite_id=str(invitation.id),
                    status=invitation.status.value,
                    expires_at=invitation.expires_at.isoformat(),
                )
            )
