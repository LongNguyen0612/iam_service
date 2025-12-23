"""
IAM Service Domain Entities - Backward Compatibility Shim

This file re-exports all entities from the new entities/ module structure.
All entities have been moved to individual files in src/domain/entities/

DEPRECATED: Import from src.domain.entities directly instead of src.domain.entities
"""

# Re-export everything from the new structure for backward compatibility
from .entities.enums import (
    UserStatus,
    TenantStatus,
    MembershipRole,
    MembershipStatus,
    InvitationStatus,
)
from .entities.user import User
from .entities.tenant import Tenant
from .entities.membership import Membership
from .entities.invitation import Invitation
from .entities.session import Session
from .entities.audit_event import AuditEvent
from .entities.password_reset_token import PasswordResetToken

__all__ = [
    # Enums
    "UserStatus",
    "TenantStatus",
    "MembershipRole",
    "MembershipStatus",
    "InvitationStatus",
    # Entities
    "User",
    "Tenant",
    "Membership",
    "Invitation",
    "Session",
    "AuditEvent",
    "PasswordResetToken",
]
