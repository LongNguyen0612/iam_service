from typing import Optional

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from src.app.repositories.password_reset_token_repository import IPasswordResetTokenRepository
from src.domain.entities import PasswordResetToken


class PasswordResetTokenRepository(IPasswordResetTokenRepository):
    """PasswordResetToken repository implementation using SQLModel"""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, token: PasswordResetToken) -> PasswordResetToken:
        """Create a new password reset token"""
        self.session.add(token)
        await self.session.flush()
        await self.session.refresh(token)
        return token

    async def get_by_token_hash(self, token_hash: str) -> Optional[PasswordResetToken]:
        """Get password reset token by token hash"""
        stmt = select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash)
        result = await self.session.exec(stmt)
        return result.one_or_none()

    async def update(self, token: PasswordResetToken) -> PasswordResetToken:
        """Update existing password reset token"""
        self.session.add(token)
        await self.session.flush()
        await self.session.refresh(token)
        return token
