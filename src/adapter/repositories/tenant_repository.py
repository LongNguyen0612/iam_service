from typing import Optional
from uuid import UUID

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from src.app.repositories.tenant_repository import ITenantRepository
from src.domain.entities import Tenant


class TenantRepository(ITenantRepository):
    """Tenant repository implementation using SQLModel"""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_by_id(self, tenant_id: UUID) -> Optional[Tenant]:
        """Get tenant by ID"""
        stmt = select(Tenant).where(Tenant.id == tenant_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def create(self, tenant: Tenant) -> Tenant:
        """Create a new tenant"""
        self.session.add(tenant)
        await self.session.flush()
        await self.session.refresh(tenant)
        return tenant

    async def update(self, tenant: Tenant) -> Tenant:
        """Update existing tenant"""
        self.session.add(tenant)
        await self.session.flush()
        await self.session.refresh(tenant)
        return tenant
