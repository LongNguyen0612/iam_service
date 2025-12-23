"""
Confirm Password Reset Use Case

Handles password reset confirmation with secure token validation.
Implements IAM-013: Confirm Password Reset.
"""

import hashlib
import bcrypt
from datetime import datetime

from libs.result import Error, Result, Return
from src.app.services.unit_of_work import UnitOfWork
from src.domain.entities import AuditEvent
from .dtos import ConfirmPasswordResetResponse


class ConfirmPasswordResetUseCase:
    """
    Use case for confirming password reset.

    Business Rules:
    - Token is validated by hashing and comparing with stored hash
    - Token must not be expired (1 hour window)
    - Token must not already be used
    - New password must meet complexity requirements (min 8 chars)
    - Password is hashed with bcrypt (cost factor 12)
    - All user sessions are revoked for security
    - Token is marked as used after successful reset
    - Audit event created for security tracking
    """

    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    def _validate_password(self, password: str) -> Result[None]:
        """
        Validate password complexity.

        Args:
            password: Password to validate

        Returns:
            Result with None if valid, or Error if invalid
        """
        if len(password) < 8:
            return Return.err(
                Error(
                    "INVALID_PASSWORD",
                    "Password must be at least 8 characters long",
                )
            )

        # Add more complexity rules here if needed
        # For now, just checking minimum length

        return Return.ok(None)

    async def execute(self, token: str, new_password: str) -> Result[ConfirmPasswordResetResponse]:
        """
        Execute confirm password reset use case.

        Args:
            token: Password reset token (plain text from email)
            new_password: New password to set

        Returns:
            Result with confirmation status, or Error

        Errors:
            - INVALID_TOKEN: Token not found or invalid
            - TOKEN_EXPIRED: Token has expired
            - TOKEN_ALREADY_USED: Token has already been used
            - INVALID_PASSWORD: Password does not meet complexity requirements
        """
        async with self.uow:
            # AC-13.4: Validate new password
            password_validation = self._validate_password(new_password)
            if password_validation.is_err():
                return Return.err(password_validation.error)

            # Hash the submitted token with SHA-256 to find it in database
            token_hash = hashlib.sha256(token.encode()).hexdigest()

            # AC-13.1: Find token by hash
            reset_token = await self.uow.password_reset_tokens.get_by_token_hash(token_hash)

            # AC-13.2: Invalid token handling
            if reset_token is None:
                return Return.err(
                    Error(
                        "INVALID_TOKEN",
                        "Invalid or expired password reset token",
                    )
                )

            # AC-13.3: Check if token is expired
            if reset_token.expires_at < datetime.utcnow():
                return Return.err(
                    Error(
                        "TOKEN_EXPIRED",
                        "Password reset token has expired",
                    )
                )

            # AC-13.1: Check if token has already been used
            if reset_token.used:
                return Return.err(
                    Error(
                        "TOKEN_ALREADY_USED",
                        "Password reset token has already been used",
                    )
                )

            # Get the user
            user = await self.uow.users.get_by_id(reset_token.user_id)
            if user is None:
                # This shouldn't happen (foreign key constraint), but handle gracefully
                return Return.err(
                    Error(
                        "USER_NOT_FOUND",
                        "User not found",
                    )
                )

            # AC-13.1: Hash new password with bcrypt
            password_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt(12))

            # Update user password
            user.password_hash = password_hash.decode()
            await self.uow.users.update(user)

            # AC-13.1: Mark token as used
            reset_token.used = True
            await self.uow.password_reset_tokens.update(reset_token)

            # AC-13.1: Revoke all sessions for security
            revoked_count = await self.uow.sessions.revoke_all_by_user_id(user.id)

            # Create audit event for security tracking
            audit_event = AuditEvent(
                tenant_id=None,  # No tenant context for password reset
                user_id=user.id,
                action="password_reset_confirmed",
                event_metadata={
                    "token_id": str(reset_token.id),
                    "sessions_revoked": revoked_count,
                },
            )
            await self.uow.audit_events.create(audit_event)

            # Commit transaction
            await self.uow.commit()

            return Return.ok(
                ConfirmPasswordResetResponse(
                    status="success",
                    message="Password has been reset successfully",
                )
            )
