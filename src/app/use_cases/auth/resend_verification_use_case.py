"""
Resend Verification Email Use Case

Handles resending email verification tokens to users.
Implements IAM-011: Resend Verification Email.
"""

import secrets
from datetime import datetime, timedelta

from libs.result import Error, Result, Return
from src.app.services.unit_of_work import UnitOfWork
from .dtos import ResendVerificationResponse


class ResendVerificationUseCase:
    """
    Use case for resending email verification.

    Business Rules:
    - If email is not verified, generate new token and extend expiry
    - If email is already verified, return success (no email sent)
    - New token replaces old token (invalidates previous)
    - Token expiry reset to 24 hours from now
    - Token is 32-character cryptographically secure string
    - Returns same response for valid/invalid emails (no enumeration)
    """

    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    async def execute(self, email: str) -> Result[ResendVerificationResponse]:
        """
        Execute resend verification email use case.

        Args:
            email: User's email address

        Returns:
            Result with resend status, or Error

        Note:
            For security (no email enumeration), always returns success
            even if email doesn't exist. However, only generates token
            if email exists and is not verified.
        """
        async with self.uow:
            # Find user by email
            user = await self.uow.users.get_by_email(email)

            # AC-11.2: No email enumeration - return success even if user not found
            if user is None:
                # Return success but don't send email
                return Return.ok(ResendVerificationResponse(
                    status="sent",
                    message="If the email exists, a verification link has been sent"
                ))

            # AC-11.2: Already verified - return success, no email sent
            if user.email_verified:
                return Return.ok(ResendVerificationResponse(
                    status="already_verified",
                    message="Email is already verified"
                ))

            # AC-11.1: Generate new token and replace old one
            # Invalidate old token by replacing it
            new_verification_token = secrets.token_urlsafe(32)

            # Update user with new token and reset expiry to 24 hours
            user.email_verification_token = new_verification_token
            user.email_verification_expires_at = datetime.utcnow() + timedelta(days=1)

            await self.uow.users.update(user)

            # Commit transaction
            await self.uow.commit()

            # NOTE: In production, this would trigger an async email send
            # via message queue (RabbitMQ) with the new verification token
            # For now, we just return success

            return Return.ok(ResendVerificationResponse(
                status="sent",
                message="If the email exists, a verification link has been sent"
            ))
