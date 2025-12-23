from typing import List, Optional
from uuid import UUID

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from src.app.repositories.membership_repository import IMembershipRepository
from src.domain.entities import Membership


class MembershipRepository(IMembershipRepository):
    """Membership repository implementation using SQLModel"""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_by_id(self, membership_id: UUID) -> Optional[Membership]:
        """Get membership by ID"""
        stmt = select(Membership).where(Membership.id == membership_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_user_and_tenant(
        self, user_id: UUID, tenant_id: UUID
    ) -> Optional[Membership]:
        """Get membership by user and tenant"""
        stmt = select(Membership).where(
            Membership.user_id == user_id, Membership.tenant_id == tenant_id
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_user_id(self, user_id: UUID) -> List[Membership]:
        """Get all memberships for a user"""
        stmt = select(Membership).where(Membership.user_id == user_id)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def create(self, membership: Membership) -> Membership:
        """Create a new membership"""
        self.session.add(membership)
        await self.session.flush()
        await self.session.refresh(membership)
        return membership

    async def update(self, membership: Membership) -> Membership:
        """Update existing membership"""
        self.session.add(membership)
        await self.session.flush()
        await self.session.refresh(membership)
        return membership

    async def get_by_tenant_id(self, tenant_id: UUID) -> List[Membership]:
        """Get all memberships for a tenant"""
        stmt = select(Membership).where(Membership.tenant_id == tenant_id)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
