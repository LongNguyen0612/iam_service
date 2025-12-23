from abc import ABC, abstractmethod
from typing import Optional
from uuid import UUID

from src.domain.entities import User


class IUserRepository(ABC):
    """User repository interface - application layer"""

    @abstractmethod
    async def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email address"""
        pass

    @abstractmethod
    async def get_by_id(self, user_id: UUID) -> Optional[User]:
        """Get user by ID"""
        pass

    @abstractmethod
    async def create(self, user: User) -> User:
        """Create a new user"""
        pass

    @abstractmethod
    async def update(self, user: User) -> User:
        """Update existing user"""
        pass

    @abstractmethod
    async def get_by_verification_token(self, token: str) -> Optional[User]:
        """Get user by email verification token"""
        pass
