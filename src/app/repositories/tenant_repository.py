from abc import ABC, abstractmethod
from typing import Optional
from uuid import UUID

from src.domain.entities import Tenant


class ITenantRepository(ABC):
    """Tenant repository interface - application layer"""

    @abstractmethod
    async def get_by_id(self, tenant_id: UUID) -> Optional[Tenant]:
        """Get tenant by ID"""
        pass

    @abstractmethod
    async def create(self, tenant: Tenant) -> Tenant:
        """Create a new tenant"""
        pass

    @abstractmethod
    async def update(self, tenant: Tenant) -> Tenant:
        """Update existing tenant"""
        pass
