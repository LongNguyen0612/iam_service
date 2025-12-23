"""
Revoke Sessions Use Case

Handles session revocation for security and session management.
"""

from typing import Optional
from uuid import UUID

from libs.result import Error, Result, Return
from src.app.services.unit_of_work import UnitOfWork
from src.domain.entities import MembershipRole


class RevokeSessionsUseCase:
    """
    Use case for revoking user sessions.

    Business Rules:
    - Users can revoke their own sessions
    - Admins can revoke any user's sessions within their tenant
    - Revocation is audit-logged for security compliance
    - Three revocation modes: all, specific, all-except-current
    """

    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    async def revoke_all_sessions(
        self,
        target_user_id: UUID,
        requesting_user_id: UUID,
        requesting_tenant_id: UUID,
        requesting_role: str,
    ) -> Result[dict]:
        """
        Revoke all sessions for a user.

        Args:
            target_user_id: User whose sessions will be revoked
            requesting_user_id: User requesting the revocation
            requesting_tenant_id: Current tenant context
            requesting_role: Role of requesting user

        Returns:
            Result with count of revoked sessions, or Error
        """
        async with self.uow:
            # Authorization: user revoking own sessions OR admin/owner
            is_self = target_user_id == requesting_user_id
            is_admin = requesting_role in (
                MembershipRole.admin.value,
                MembershipRole.owner.value,
            )

            if not is_self and not is_admin:
                return Return.err(
                    Error(
                        "FORBIDDEN",
                        "Only admins can revoke other users' sessions",
                    )
                )

            # Verify target user exists
            target_user = await self.uow.users.get_by_id(target_user_id)
            if not target_user:
                return Return.err(Error("USER_NOT_FOUND", "User not found"))

            # Revoke all sessions
            count = await self.uow.sessions.revoke_all_by_user_id(target_user_id)

            # Create audit event
            from src.domain.entities import AuditEvent

            audit = AuditEvent(
                tenant_id=requesting_tenant_id,
                user_id=requesting_user_id,
                action="revoke_all_sessions",
                event_metadata={
                    "target_user_id": str(target_user_id),
                    "revoked_count": count,
                    "is_self": is_self,
                },
            )
            await self.uow.audit_events.create(audit)

            await self.uow.commit()

            return Return.ok({"revoked_count": count, "target_user_id": str(target_user_id)})

    async def revoke_specific_session(
        self,
        session_id: UUID,
        requesting_user_id: UUID,
        requesting_tenant_id: UUID,
        requesting_role: str,
    ) -> Result[dict]:
        """
        Revoke a specific session by ID.

        Args:
            session_id: Session to revoke
            requesting_user_id: User requesting the revocation
            requesting_tenant_id: Current tenant context
            requesting_role: Role of requesting user

        Returns:
            Result with success status, or Error
        """
        async with self.uow:
            # Get the session
            session = await self.uow.sessions.get_by_id(session_id)
            if not session:
                return Return.err(Error("SESSION_NOT_FOUND", "Session not found"))

            # Authorization: user revoking own session OR admin/owner
            is_self = session.user_id == requesting_user_id
            is_admin = requesting_role in (
                MembershipRole.admin.value,
                MembershipRole.owner.value,
            )

            if not is_self and not is_admin:
                return Return.err(
                    Error("FORBIDDEN", "Only admins can revoke other users' sessions")
                )

            # Check if already revoked
            if session.revoked:
                return Return.err(Error("SESSION_ALREADY_REVOKED", "Session already revoked"))

            # Revoke the session
            success = await self.uow.sessions.revoke_by_id(session_id)

            # Create audit event
            from src.domain.entities import AuditEvent

            audit = AuditEvent(
                tenant_id=requesting_tenant_id,
                user_id=requesting_user_id,
                action="revoke_session",
                event_metadata={
                    "session_id": str(session_id),
                    "target_user_id": str(session.user_id),
                    "is_self": is_self,
                },
            )
            await self.uow.audit_events.create(audit)

            await self.uow.commit()

            return Return.ok({"session_id": str(session_id), "revoked": success})

    async def revoke_all_except_current(
        self,
        current_session_id: UUID,
        requesting_user_id: UUID,
        requesting_tenant_id: UUID,
    ) -> Result[dict]:
        """
        Revoke all sessions for the user except the current session.

        This is a self-service operation (logout other devices).

        Args:
            current_session_id: Session to keep active
            requesting_user_id: User requesting the revocation
            requesting_tenant_id: Current tenant context

        Returns:
            Result with count of revoked sessions, or Error
        """
        async with self.uow:
            # Verify current session exists and belongs to user
            current_session = await self.uow.sessions.get_by_id(current_session_id)
            if not current_session:
                return Return.err(Error("SESSION_NOT_FOUND", "Current session not found"))

            if current_session.user_id != requesting_user_id:
                return Return.err(
                    Error("FORBIDDEN", "Session does not belong to current user")
                )

            # Revoke all except current
            count = await self.uow.sessions.revoke_all_except_session(
                requesting_user_id, current_session_id
            )

            # Create audit event
            from src.domain.entities import AuditEvent

            audit = AuditEvent(
                tenant_id=requesting_tenant_id,
                user_id=requesting_user_id,
                action="revoke_other_sessions",
                event_metadata={
                    "kept_session_id": str(current_session_id),
                    "revoked_count": count,
                },
            )
            await self.uow.audit_events.create(audit)

            await self.uow.commit()

            return Return.ok(
                {
                    "revoked_count": count,
                    "kept_session_id": str(current_session_id),
                }
            )
