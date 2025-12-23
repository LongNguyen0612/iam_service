"""
Login Use Case

Handles user authentication and returns tenant-scoped JWT tokens.
"""

import bcrypt
import secrets
from datetime import UTC, datetime, timedelta

from libs.result import Error, Result, Return
from src.app.services.unit_of_work import UnitOfWork
from src.domain.entities import MembershipStatus, Session, UserStatus
from src.api.utils.jwt import generate_jwt
from .dtos import LoginResponse, TenantInfo


class LoginUseCase:
    """
    Use case for user login and JWT issuance.

    Business Rules:
    - Constant-time password comparison to prevent timing attacks
    - User must have status=active
    - User must have at least one active membership
    - JWT scoped to last_active_tenant_id or most recent membership
    - Creates new session with refresh token
    - Updates user.last_login_at
    """

    def __init__(self, uow: UnitOfWork):
        self.uow = uow

    async def execute(self, email: str, password: str) -> Result[LoginResponse]:
        """
        Execute login use case.

        Args:
            email: User email
            password: Plain text password

        Returns:
            Result with LoginResponse containing tokens and tenant info, or Error
        """
        async with self.uow:
            # Get user by email
            user = await self.uow.users.get_by_email(email)

            # Constant-time password verification (prevent timing attacks)
            # Always perform hash check even if user not found
            if user is None:
                # Hash dummy password to maintain constant time
                bcrypt.checkpw(b"dummy_password", bcrypt.gensalt(12))
                return Return.err(
                    Error("INVALID_CREDENTIALS", "Invalid email or password")
                )

            # Verify password
            password_valid = bcrypt.checkpw(
                password.encode(), user.password_hash.encode()
            )

            if not password_valid:
                return Return.err(
                    Error("INVALID_CREDENTIALS", "Invalid email or password")
                )

            # Check user status
            if user.status == UserStatus.disabled:
                return Return.err(Error("USER_DISABLED", "User account is disabled"))

            # Get all memberships
            memberships = await self.uow.memberships.get_by_user_id(user.id)

            # Filter active memberships
            active_memberships = [
                m for m in memberships if m.status == MembershipStatus.active
            ]

            if not active_memberships:
                return Return.err(
                    Error(
                        "NO_ACTIVE_MEMBERSHIP",
                        "User has no active tenant memberships",
                    )
                )

            # Determine active tenant (last_active_tenant_id or most recent)
            active_membership = None
            if user.last_active_tenant_id:
                # Find membership for last active tenant
                for m in active_memberships:
                    if m.tenant_id == user.last_active_tenant_id:
                        active_membership = m
                        break

            # If no last active tenant or membership not found, use most recent
            if active_membership is None:
                active_membership = max(
                    active_memberships, key=lambda m: m.created_at
                )

            # Get tenant details
            tenant = await self.uow.tenants.get_by_id(active_membership.tenant_id)
            if tenant is None:
                return Return.err(Error("TENANT_NOT_FOUND", "Tenant not found"))

            # Generate refresh token
            refresh_token = secrets.token_urlsafe(32)
            refresh_token_hash = bcrypt.hashpw(
                refresh_token.encode(), bcrypt.gensalt(12)
            )

            # Create session
            session = Session(
                user_id=user.id,
                tenant_id=tenant.id,
                refresh_token_hash=refresh_token_hash.decode(),
                expires_at=datetime.now(UTC) + timedelta(days=30),
            )
            await self.uow.sessions.create(session)

            # Update last_login_at and last_active_tenant_id
            user.last_login_at = datetime.now(UTC)
            user.last_active_tenant_id = tenant.id
            await self.uow.users.update(user)

            # Create audit event
            from src.domain.entities import AuditEvent

            audit = AuditEvent(
                tenant_id=tenant.id,
                user_id=user.id,
                action="login",
                metadata={"email": email, "tenant_name": tenant.name},
            )
            await self.uow.audit_events.create(audit)

            # Commit transaction
            await self.uow.commit()

            # Generate JWT
            access_token = generate_jwt(
                user.id, tenant.id, active_membership.role.value
            )

            # Build other_tenants list
            other_tenants = []
            for m in active_memberships:
                if m.tenant_id != tenant.id:
                    other_tenant = await self.uow.tenants.get_by_id(m.tenant_id)
                    if other_tenant:
                        other_tenants.append(
                            TenantInfo(
                                id=str(other_tenant.id),
                                name=other_tenant.name,
                                role=m.role.value,
                            )
                        )

            return Return.ok(
                LoginResponse(
                    access_token=access_token,
                    refresh_token=refresh_token,
                    session_id=str(session.id),
                    active_tenant=TenantInfo(
                        id=str(tenant.id),
                        name=tenant.name,
                        role=active_membership.role.value,
                    ),
                    other_tenants=other_tenants,
                )
            )
