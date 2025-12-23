import secrets
from datetime import UTC, datetime, timedelta

import bcrypt
from libs.result import Error, Result, Return

from src.app.services.unit_of_work import UnitOfWork
from .signup_dto import SignupCommand, SignupResponse
from src.domain.entities import (
    AuditEvent,
    Membership,
    MembershipRole,
    MembershipStatus,
    Session,
    Tenant,
    User,
)


class SignupUseCase:
    """
    Signup Use Case - AC-1.1, AC-1.2

    Command/Response Pattern:
    - Input: SignupCommand (validated business intent)
    - Output: Result[SignupResponse] (structured response)

    Business Logic:
    1. Check if email already exists (AC-1.2)
    2. Hash password with bcrypt cost factor 12
    3. Create User with email_verified=False
    4. Generate email verification token (32 chars, secure)
    5. Create Tenant with provided name
    6. Create Membership with role=owner, status=active
    7. Generate refresh token and hash it
    8. Create Session (expires in 30 days)
    9. Create AuditEvent with action=signup
    10. Commit transaction atomically
    11. Return SignupResponse with all data
    """

    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    async def execute(self, command: SignupCommand) -> Result[SignupResponse]:
        """
        Execute signup use case

        Args:
            command: SignupCommand with validated email, password, tenant_name

        Returns:
            Result[SignupResponse] with user and tenant data, tokens
            or Error(EMAIL_ALREADY_EXISTS) if email exists
        """
        async with self.uow:
            # AC-1.2: Check if user exists
            existing_user = await self.uow.users.get_by_email(command.email)
            if existing_user:
                return Return.err(
                    Error("EMAIL_ALREADY_EXISTS", "Email already registered")
                )

            # Hash password with bcrypt cost factor 12 (security requirement)
            password_hash = bcrypt.hashpw(
                command.password.encode("utf-8"), bcrypt.gensalt(12)
            )

            # Generate email verification token (32 chars, cryptographically secure)
            email_verification_token = secrets.token_urlsafe(32)

            # Create User entity
            user = User(
                email=command.email,
                password_hash=password_hash.decode("utf-8"),
                email_verified=False,
                email_verification_token=email_verification_token,
                email_verification_expires_at=datetime.utcnow() + timedelta(days=1),
            )
            user = await self.uow.users.create(user)

            # Create Tenant entity
            tenant = Tenant(name=command.tenant_name)
            tenant = await self.uow.tenants.create(tenant)

            # Create Membership (user is owner of their tenant)
            membership = Membership(
                user_id=user.id,
                tenant_id=tenant.id,
                role=MembershipRole.owner,
                status=MembershipStatus.active,
            )
            await self.uow.memberships.create(membership)

            # Generate refresh token and hash it
            refresh_token = secrets.token_urlsafe(32)
            refresh_token_hash = bcrypt.hashpw(
                refresh_token.encode("utf-8"), bcrypt.gensalt(12)
            )

            # Create Session (expires in 30 days)
            session = Session(
                user_id=user.id,
                tenant_id=tenant.id,
                refresh_token_hash=refresh_token_hash.decode("utf-8"),
                expires_at=datetime.utcnow() + timedelta(days=30),
            )
            await self.uow.sessions.create(session)

            # Create AuditEvent for signup action
            audit_event = AuditEvent(
                tenant_id=tenant.id,
                user_id=user.id,
                action="signup",
                event_metadata={
                    "email": command.email,
                    "tenant_name": command.tenant_name,
                },
            )
            await self.uow.audit_events.create(audit_event)

            # Commit transaction atomically
            await self.uow.commit()

            # Import JWT utility here to avoid circular dependency
            from src.api.utils.jwt import generate_jwt

            # Generate JWT access token (15-minute expiry)
            access_token = generate_jwt(
                user_id=user.id, tenant_id=tenant.id, role=MembershipRole.owner.value
            )

            # Import nested models
            from .signup_dto import UserInfo, TenantCreated

            # Return structured SignupResponse with nested models
            response = SignupResponse(
                user=UserInfo(
                    id=str(user.id),
                    email=user.email,
                    email_verified=user.email_verified,
                ),
                tenant=TenantCreated(
                    id=str(tenant.id),
                    name=tenant.name,
                ),
                access_token=access_token,
                refresh_token=refresh_token,  # Plain token (user receives this)
                session_id=str(session.id),
            )

            return Return.ok(response)
