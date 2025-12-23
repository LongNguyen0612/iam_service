from abc import ABC, abstractmethod
from typing import List, Optional
from uuid import UUID

from src.domain.entities import Membership


class IMembershipRepository(ABC):
    """Membership repository interface - application layer"""

    @abstractmethod
    async def get_by_id(self, membership_id: UUID) -> Optional[Membership]:
        """Get membership by ID"""
        pass

    @abstractmethod
    async def get_by_user_and_tenant(
        self, user_id: UUID, tenant_id: UUID
    ) -> Optional[Membership]:
        """Get membership by user and tenant"""
        pass

    @abstractmethod
    async def get_by_user_id(self, user_id: UUID) -> List[Membership]:
        """Get all memberships for a user"""
        pass

    @abstractmethod
    async def create(self, membership: Membership) -> Membership:
        """Create a new membership"""
        pass

    @abstractmethod
    async def update(self, membership: Membership) -> Membership:
        """Update existing membership"""
        pass

    @abstractmethod
    async def get_by_tenant_id(self, tenant_id: UUID) -> List[Membership]:
        """Get all memberships for a tenant"""
        pass
