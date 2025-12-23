from abc import ABC, abstractmethod
from typing import List, Optional
from uuid import UUID

from src.domain.entities import Session


class ISessionRepository(ABC):
    """Session repository interface - application layer"""

    @abstractmethod
    async def get_by_id(self, session_id: UUID) -> Optional[Session]:
        """Get session by ID"""
        pass

    @abstractmethod
    async def get_by_user_id(self, user_id: UUID) -> List[Session]:
        """Get all sessions for a user"""
        pass

    @abstractmethod
    async def create(self, session: Session) -> Session:
        """Create a new session"""
        pass

    @abstractmethod
    async def update(self, session: Session) -> Session:
        """Update existing session"""
        pass

    @abstractmethod
    async def find_by_refresh_token(self, refresh_token: str) -> Optional[Session]:
        """Find session by verifying refresh token hash (bcrypt)"""
        pass

    @abstractmethod
    async def revoke_all_by_user_id(self, user_id: UUID) -> int:
        """Revoke all sessions for a user. Returns count of revoked sessions."""
        pass

    @abstractmethod
    async def revoke_all_except_session(self, user_id: UUID, session_id: UUID) -> int:
        """Revoke all sessions for a user except the specified session. Returns count."""
        pass

    @abstractmethod
    async def revoke_by_id(self, session_id: UUID) -> bool:
        """Revoke a specific session. Returns True if session existed and was revoked."""
        pass

    @abstractmethod
    async def get_active_by_tenant_id(self, tenant_id: UUID) -> List[Session]:
        """Get all active (non-revoked) sessions for a tenant"""
        pass

    @abstractmethod
    async def get_by_user_and_tenant(
        self, user_id: UUID, tenant_id: UUID
    ) -> List[Session]:
        """Get all sessions for a user in a specific tenant"""
        pass
