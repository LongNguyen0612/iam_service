from sqlmodel.ext.asyncio.session import AsyncSession

from src.adapter.repositories.audit_event_repository import AuditEventRepository
from src.adapter.repositories.invitation_repository import InvitationRepository
from src.adapter.repositories.membership_repository import MembershipRepository
from src.adapter.repositories.password_reset_token_repository import PasswordResetTokenRepository
from src.adapter.repositories.session_repository import SessionRepository
from src.adapter.repositories.tenant_repository import TenantRepository
from src.adapter.repositories.user_repository import UserRepository
from src.app.services.unit_of_work import UnitOfWork


class SqlAlchemyUnitOfWork(UnitOfWork):
    """SQLAlchemy implementation of UnitOfWork pattern"""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def __aenter__(self):
        # Initialize all repositories with the session
        self.users = UserRepository(self.session)
        self.tenants = TenantRepository(self.session)
        self.memberships = MembershipRepository(self.session)
        self.sessions = SessionRepository(self.session)
        self.invitations = InvitationRepository(self.session)
        self.audit_events = AuditEventRepository(self.session)
        self.password_reset_tokens = PasswordResetTokenRepository(self.session)
        return self

    async def __aexit__(self, *args):
        await self.rollback()

    async def commit(self):
        await self.session.commit()

    async def rollback(self):
        await self.session.rollback()
