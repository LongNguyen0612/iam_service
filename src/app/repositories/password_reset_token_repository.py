from abc import ABC, abstractmethod
from typing import Optional
from uuid import UUID

from src.domain.entities import PasswordResetToken


class IPasswordResetTokenRepository(ABC):
    """PasswordResetToken repository interface - application layer"""

    @abstractmethod
    async def create(self, token: PasswordResetToken) -> PasswordResetToken:
        """Create a new password reset token"""
        pass

    @abstractmethod
    async def get_by_token_hash(self, token_hash: str) -> Optional[PasswordResetToken]:
        """Get password reset token by token hash"""
        pass

    @abstractmethod
    async def update(self, token: PasswordResetToken) -> PasswordResetToken:
        """Update existing password reset token"""
        pass
