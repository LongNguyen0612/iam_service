"""
Verify Email Use Case

Handles email verification via secure token.
Implements IAM-010: Email Verification.
"""

from datetime import datetime

from libs.result import Error, Result, Return
from src.app.services.unit_of_work import UnitOfWork
from src.domain.entities import AuditEvent
from .dtos import VerifyEmailResponse


class VerifyEmailUseCase:
    """
    Use case for email verification.

    Business Rules:
    - Token must match user's email_verification_token
    - Token must not be expired (24 hours from signup)
    - Sets email_verified = True
    - Clears verification token (single-use)
    - Already verified users return success
    - Records audit event
    """

    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    async def execute(self, token: str) -> Result[VerifyEmailResponse]:
        """
        Execute email verification use case.

        Args:
            token: Verification token from email link

        Returns:
            Result with verification status, or Error

        Errors:
            - INVALID_TOKEN: Token not found or user not found
            - TOKEN_EXPIRED: Token has expired (>24 hours)
        """
        async with self.uow:
            # Find user by verification token
            user = await self.uow.users.get_by_verification_token(token)

            if user is None:
                return Return.err(
                    Error(
                        "INVALID_TOKEN",
                        "Invalid or non-existent verification token"
                    )
                )

            # Check if already verified
            if user.email_verified:
                # Return success - idempotent operation
                return Return.ok(VerifyEmailResponse(
                    status="verified",
                    message="Email is already verified"
                ))

            # Check if token has expired
            if user.email_verification_expires_at is None:
                return Return.err(
                    Error(
                        "INVALID_TOKEN",
                        "Verification token data is invalid"
                    )
                )

            current_time = datetime.utcnow()
            if current_time > user.email_verification_expires_at:
                return Return.err(
                    Error(
                        "TOKEN_EXPIRED",
                        "Verification token has expired. Please request a new verification email."
                    )
                )

            # Verify email - set verified flag and clear token
            user.email_verified = True
            user.email_verification_token = None
            user.email_verification_expires_at = None

            await self.uow.users.update(user)

            # Create audit event
            audit = AuditEvent(
                tenant_id=None,  # No tenant context yet for verification
                user_id=user.id,
                action="email_verified",
                event_metadata={"email": user.email}
            )
            await self.uow.audit_events.create(audit)

            # Commit transaction
            await self.uow.commit()

            return Return.ok(VerifyEmailResponse(
                status="verified",
                message="Email successfully verified"
            ))
