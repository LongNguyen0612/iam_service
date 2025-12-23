"""
Request Password Reset Use Case

Handles generating and sending password reset tokens.
Implements IAM-012: Request Password Reset.
"""

import hashlib
import secrets
from datetime import datetime, timedelta

from libs.result import Result, Return
from src.app.services.unit_of_work import UnitOfWork
from src.domain.entities import PasswordResetToken, AuditEvent
from .dtos import RequestPasswordResetResponse


class RequestPasswordResetUseCase:
    """
    Use case for requesting password reset.

    Business Rules:
    - Generate cryptographically secure 32-character token
    - Hash token with SHA-256 before storing
    - Token expires in 1 hour
    - No email enumeration (same response for valid/invalid emails)
    - Rate limiting to be handled at middleware/infrastructure layer
    - Audit event created for security tracking
    """

    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    async def execute(self, email: str) -> Result[RequestPasswordResetResponse]:
        """
        Execute request password reset use case.

        Args:
            email: User's email address

        Returns:
            Result with reset status, or Error

        Note:
            For security (no email enumeration), always returns success
            even if email doesn't exist. However, only generates token
            if email exists.
        """
        async with self.uow:
            # Find user by email
            user = await self.uow.users.get_by_email(email)

            # AC-12.2: No email enumeration - return success even if user not found
            if user is None:
                # Return success but don't send email or create token
                return Return.ok(
                    RequestPasswordResetResponse(
                        status="sent",
                        message="If the email exists, a password reset link has been sent",
                    )
                )

            # AC-12.1: Generate secure token
            # Generate 32-byte cryptographically secure token
            reset_token = secrets.token_urlsafe(32)

            # Hash token with SHA-256 for storage
            token_hash = hashlib.sha256(reset_token.encode()).hexdigest()

            # AC-12.1: Create password reset token (expires in 1 hour)
            password_reset_token = PasswordResetToken(
                user_id=user.id,
                token_hash=token_hash,
                used=False,
                expires_at=datetime.utcnow() + timedelta(hours=1),
            )

            await self.uow.password_reset_tokens.create(password_reset_token)

            # Create audit event for security tracking
            audit_event = AuditEvent(
                tenant_id=None,  # No tenant context for password reset
                user_id=user.id,
                action="password_reset_requested",
                event_metadata={"email": email, "token_id": str(password_reset_token.id)},
            )
            await self.uow.audit_events.create(audit_event)

            # Commit transaction
            await self.uow.commit()

            # NOTE: In production, this would trigger an async email send
            # via message queue (RabbitMQ) with the reset_token (NOT the hash)
            # The email would contain a link like:
            # https://app.example.com/reset-password?token={reset_token}
            #
            # For now, we just return success
            # AC-12.3: Rate limiting is handled at middleware/infrastructure layer

            return Return.ok(
                RequestPasswordResetResponse(
                    status="sent",
                    message="If the email exists, a password reset link has been sent",
                )
            )
