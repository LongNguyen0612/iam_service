"""
Use Cases - Backward Compatibility Shim

All use cases have been organized into domain folders:
- auth/: Authentication flows
- tenants/: Tenant management
- users/: User management
- audit/: Audit logs

Import from subdirectories for better organization.
"""

# Re-export everything for backward compatibility
from .auth import (
    SignupUseCase,
    SignupCommand,
    SignupResponse,
    LoginUseCase,
    RefreshTokenUseCase,
    VerifyEmailUseCase,
    ResendVerificationUseCase,
)
from .tenants import (
    SwitchTenantUseCase,
    InviteUserUseCase,
)
from .users import (
    LoadContextUseCase,
    ChangeRoleUseCase,
    RevokeSessionsUseCase,
)
from .audit import (
    GetAuditEventsUseCase,
)

__all__ = [
    # Auth
    "SignupUseCase",
    "SignupCommand",
    "SignupResponse",
    "LoginUseCase",
    "RefreshTokenUseCase",
    "VerifyEmailUseCase",
    "ResendVerificationUseCase",
    # Tenants
    "SwitchTenantUseCase",
    "InviteUserUseCase",
    # Users
    "LoadContextUseCase",
    "ChangeRoleUseCase",
    "RevokeSessionsUseCase",
    # Audit
    "GetAuditEventsUseCase",
]
