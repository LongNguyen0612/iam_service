"""
Refresh Token Use Case

Handles JWT token refresh with refresh token rotation for security.
"""

import bcrypt
import secrets
from datetime import datetime, timedelta

from libs.result import Error, Result, Return
from src.app.services.unit_of_work import UnitOfWork
from src.domain.entities import MembershipStatus
from src.api.utils.jwt import generate_jwt
from .dtos import RefreshTokenResponse


class RefreshTokenUseCase:
    """
    Use case for refreshing JWT access tokens.

    Business Rules:
    - Refresh token rotation: old token invalidated, new token issued
    - Session must not be revoked
    - Session must not be expired
    - Membership must still be active
    - Token hash verification using bcrypt (constant-time)
    """

    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    async def execute(self, refresh_token: str) -> Result[RefreshTokenResponse]:
        """
        Execute refresh token use case.

        Args:
            refresh_token: The refresh token to verify and rotate

        Returns:
            Result with RefreshTokenResponse containing new tokens, or Error
        """
        async with self.uow:
            # Find session by verifying refresh token hash
            matching_session = await self.uow.sessions.find_by_refresh_token(
                refresh_token
            )

            if matching_session is None:
                return Return.err(Error("INVALID_TOKEN", "Invalid refresh token"))

            # Check if session is revoked
            if matching_session.revoked:
                return Return.err(Error("SESSION_REVOKED", "Session has been revoked"))

            # Check if session is expired
            if matching_session.expires_at < datetime.utcnow():
                return Return.err(Error("SESSION_EXPIRED", "Session has expired"))

            # Get membership for the session's tenant
            membership = await self.uow.memberships.get_by_user_and_tenant(
                matching_session.user_id, matching_session.tenant_id
            )

            if membership is None or membership.status != MembershipStatus.active:
                return Return.err(
                    Error("MEMBERSHIP_REVOKED", "Membership has been revoked")
                )

            # Generate new refresh token
            new_refresh_token = secrets.token_urlsafe(32)
            new_refresh_token_hash = bcrypt.hashpw(
                new_refresh_token.encode(), bcrypt.gensalt(12)
            )

            # Update session with new token hash (token rotation)
            matching_session.refresh_token_hash = new_refresh_token_hash.decode()
            matching_session.expires_at = datetime.utcnow() + timedelta(days=30)
            await self.uow.sessions.update(matching_session)

            # Create audit event
            from src.domain.entities import AuditEvent

            audit = AuditEvent(
                tenant_id=matching_session.tenant_id,
                user_id=matching_session.user_id,
                action="token_refresh",
                metadata={"session_id": str(matching_session.id)},
            )
            await self.uow.audit_events.create(audit)

            # Commit transaction
            await self.uow.commit()

            # Generate new JWT access token
            access_token = generate_jwt(
                matching_session.user_id,
                matching_session.tenant_id,
                membership.role.value,
            )

            return Return.ok(
                RefreshTokenResponse(
                    access_token=access_token,
                    refresh_token=new_refresh_token,
                    session_id=str(matching_session.id),
                )
            )
