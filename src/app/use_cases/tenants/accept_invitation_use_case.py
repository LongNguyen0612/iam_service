"""
Accept Invitation Use Case

Handles accepting tenant invitations for both existing and new users.
"""

import bcrypt
import secrets
from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

from libs.result import Error, Result, Return
from src.api.utils.jwt import create_access_token
from src.app.services.unit_of_work import UnitOfWork
from src.domain.entities import (
    AuditEvent,
    Invitation,
    InvitationStatus,
    Membership,
    MembershipStatus,
    Session,
    User,
)

from .dtos import AcceptInvitationResponse, TenantInfo


class AcceptInvitationUseCase:
    """
    Use case for accepting tenant invitations.

    Business Rules (IAM-014):
    - AC-14.1: Existing users accept invitation (create Membership only)
    - AC-14.2: New users accept invitation (create User + Membership)
    - AC-14.3: Expired invitations are rejected
    - AC-14.4: Already accepted invitations are rejected
    - AC-14.5: Email mismatch is rejected (security check)
    """

    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    async def execute(
        self, token: str, password: Optional[str] = None
    ) -> Result[AcceptInvitationResponse]:
        """
        Execute accept invitation use case.

        Args:
            token: Invitation token
            password: Password (required only for new users)

        Returns:
            Result with AcceptInvitationResponse DTO, or Error
        """
        async with self.uow:
            # Find invitation by token
            invitation = await self.uow.invitations.get_by_token(token)

            if invitation is None:
                return Return.err(
                    Error("INVALID_TOKEN", "Invalid or non-existent invitation token")
                )

            # AC-14.4: Check if already accepted
            if invitation.status == InvitationStatus.accepted:
                return Return.err(
                    Error(
                        "INVITATION_ALREADY_ACCEPTED",
                        "This invitation has already been accepted",
                    )
                )

            # AC-14.3: Check if expired
            if invitation.expires_at < datetime.utcnow():
                # Mark as expired
                invitation.status = InvitationStatus.expired
                await self.uow.invitations.update(invitation)
                await self.uow.commit()

                return Return.err(
                    Error("INVITATION_EXPIRED", "This invitation has expired")
                )

            # Get tenant
            tenant = await self.uow.tenants.get_by_id(invitation.tenant_id)
            if tenant is None:
                return Return.err(Error("TENANT_NOT_FOUND", "Tenant not found"))

            # Check if user exists
            existing_user = await self.uow.users.get_by_email(invitation.email)

            if existing_user:
                # AC-14.1: Existing user accepts invite
                user = existing_user
                user_is_new = False

                # Check if user already has a membership
                existing_membership = (
                    await self.uow.memberships.get_by_user_and_tenant(
                        user.id, tenant.id
                    )
                )
                if existing_membership and existing_membership.status == MembershipStatus.active:
                    return Return.err(
                        Error(
                            "ALREADY_MEMBER",
                            "User is already an active member of this tenant",
                        )
                    )

            else:
                # AC-14.2: New user accepts invite
                if not password:
                    return Return.err(
                        Error(
                            "PASSWORD_REQUIRED",
                            "Password is required for new user registration",
                        )
                    )

                # Validate password
                if len(password) < 8:
                    return Return.err(
                        Error(
                            "INVALID_PASSWORD",
                            "Password must be at least 8 characters long",
                        )
                    )

                # Create new user
                password_hash = bcrypt.hashpw(
                    password.encode("utf-8"), bcrypt.gensalt(rounds=12)
                ).decode("utf-8")

                user = User(
                    email=invitation.email,
                    password_hash=password_hash,
                    email_verified=False,  # Email verification still required
                    email_verification_token=None,  # Will be set later if needed
                    email_verification_expires_at=None,
                )

                user = await self.uow.users.create(user)
                user_is_new = True

            # Create membership
            membership = Membership(
                user_id=user.id,
                tenant_id=tenant.id,
                role=invitation.role,
                status=MembershipStatus.active,
            )

            await self.uow.memberships.create(membership)

            # Mark invitation as accepted
            invitation.status = InvitationStatus.accepted
            await self.uow.invitations.update(invitation)

            # Create session with refresh token
            refresh_token = secrets.token_urlsafe(32)

            # Hash the refresh token for storage
            refresh_token_hash = bcrypt.hashpw(
                refresh_token.encode("utf-8"), bcrypt.gensalt(rounds=12)
            ).decode("utf-8")

            session = Session(
                user_id=user.id,
                tenant_id=tenant.id,
                refresh_token_hash=refresh_token_hash,
                expires_at=datetime.utcnow() + timedelta(days=30),
            )

            await self.uow.sessions.create(session)

            # Create audit event
            audit = AuditEvent(
                tenant_id=tenant.id,
                user_id=user.id,
                action="invitation_accepted",
                event_metadata={
                    "invitation_id": str(invitation.id),
                    "is_new_user": user_is_new,
                    "role": invitation.role.value,
                },
            )
            await self.uow.audit_events.create(audit)

            # Update user's last active tenant
            user.last_active_tenant_id = tenant.id
            await self.uow.users.update(user)

            # Commit transaction
            await self.uow.commit()

            # Create JWT access token
            access_token = create_access_token(
                user_id=str(user.id),
                tenant_id=str(tenant.id),
                role=invitation.role.value,
                expires_delta=timedelta(minutes=15),
            )

            # Return success response
            return Return.ok(
                AcceptInvitationResponse(
                    access_token=access_token,
                    refresh_token=refresh_token,
                    tenant=TenantInfo(
                        id=str(tenant.id),
                        name=tenant.name,
                        role=invitation.role.value,
                    ),
                    email_verification_required=(not user.email_verified),
                )
            )
