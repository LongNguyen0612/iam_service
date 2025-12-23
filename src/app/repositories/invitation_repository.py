from abc import ABC, abstractmethod
from typing import List, Optional
from uuid import UUID

from src.domain.entities import Invitation


class IInvitationRepository(ABC):
    """Invitation repository interface - application layer"""

    @abstractmethod
    async def get_by_id(self, invitation_id: UUID) -> Optional[Invitation]:
        """Get invitation by ID"""
        pass

    @abstractmethod
    async def get_by_token(self, token: str) -> Optional[Invitation]:
        """Get invitation by token"""
        pass

    @abstractmethod
    async def get_pending_by_tenant_and_email(
        self, tenant_id: UUID, email: str
    ) -> Optional[Invitation]:
        """Get pending invitation by tenant and email"""
        pass

    @abstractmethod
    async def get_by_tenant_id(self, tenant_id: UUID) -> List[Invitation]:
        """Get all invitations for a tenant"""
        pass

    @abstractmethod
    async def create(self, invitation: Invitation) -> Invitation:
        """Create a new invitation"""
        pass

    @abstractmethod
    async def update(self, invitation: Invitation) -> Invitation:
        """Update existing invitation"""
        pass
