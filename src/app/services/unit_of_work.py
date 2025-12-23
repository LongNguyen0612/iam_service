from abc import ABC, abstractmethod

from src.app.repositories.audit_event_repository import IAuditEventRepository
from src.app.repositories.invitation_repository import IInvitationRepository
from src.app.repositories.membership_repository import IMembershipRepository
from src.app.repositories.password_reset_token_repository import IPasswordResetTokenRepository
from src.app.repositories.session_repository import ISessionRepository
from src.app.repositories.tenant_repository import ITenantRepository
from src.app.repositories.user_repository import IUserRepository


class UnitOfWork(ABC):
    """Abstract UnitOfWork - defines repository access and transaction management"""

    # Repository properties (initialized in __aenter__)
    users: IUserRepository
    tenants: ITenantRepository
    memberships: IMembershipRepository
    sessions: ISessionRepository
    invitations: IInvitationRepository
    audit_events: IAuditEventRepository
    password_reset_tokens: IPasswordResetTokenRepository

    @abstractmethod
    async def __aenter__(self):
        pass

    @abstractmethod
    async def __aexit__(self, *args):
        pass

    @abstractmethod
    async def commit(self):
        pass

    @abstractmethod
    async def rollback(self):
        pass
