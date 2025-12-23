"""
IAM Service Domain Enums

All enumeration types used across domain entities.
"""

from enum import Enum


class UserStatus(str, Enum):
    """User account status"""

    active = "active"
    disabled = "disabled"


class TenantStatus(str, Enum):
    """Tenant status"""

    active = "active"
    suspended = "suspended"


class MembershipRole(str, Enum):
    """User role within a tenant"""

    owner = "owner"
    admin = "admin"
    member = "member"
    viewer = "viewer"


class MembershipStatus(str, Enum):
    """Membership status"""

    active = "active"
    invited = "invited"
    revoked = "revoked"


class InvitationStatus(str, Enum):
    """Invitation status"""

    pending = "pending"
    accepted = "accepted"
    expired = "expired"
