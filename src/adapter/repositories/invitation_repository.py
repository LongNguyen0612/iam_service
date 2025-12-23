from typing import List, Optional
from uuid import UUID

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from src.app.repositories.invitation_repository import IInvitationRepository
from src.domain.entities import Invitation, InvitationStatus


class InvitationRepository(IInvitationRepository):
    """Invitation repository implementation using SQLModel"""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_by_id(self, invitation_id: UUID) -> Optional[Invitation]:
        """Get invitation by ID"""
        stmt = select(Invitation).where(Invitation.id == invitation_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_token(self, token: str) -> Optional[Invitation]:
        """Get invitation by token"""
        stmt = select(Invitation).where(Invitation.token == token)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_pending_by_tenant_and_email(
        self, tenant_id: UUID, email: str
    ) -> Optional[Invitation]:
        """Get pending invitation by tenant and email"""
        stmt = select(Invitation).where(
            Invitation.tenant_id == tenant_id,
            Invitation.email == email,
            Invitation.status == InvitationStatus.pending,
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_tenant_id(self, tenant_id: UUID) -> List[Invitation]:
        """Get all invitations for a tenant"""
        stmt = select(Invitation).where(Invitation.tenant_id == tenant_id)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def create(self, invitation: Invitation) -> Invitation:
        """Create a new invitation"""
        self.session.add(invitation)
        await self.session.flush()
        await self.session.refresh(invitation)
        return invitation

    async def update(self, invitation: Invitation) -> Invitation:
        """Update existing invitation"""
        self.session.add(invitation)
        await self.session.flush()
        await self.session.refresh(invitation)
        return invitation
