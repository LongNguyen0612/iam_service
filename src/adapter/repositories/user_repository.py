from typing import Optional
from uuid import UUID

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from src.app.repositories.user_repository import IUserRepository
from src.domain.entities import User


class UserRepository(IUserRepository):
    """User repository implementation using SQLModel"""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email address"""
        stmt = select(User).where(User.email == email)
        result = await self.session.exec(stmt)
        return result.one_or_none()

    async def get_by_id(self, user_id: UUID) -> Optional[User]:
        """Get user by ID"""
        stmt = select(User).where(User.id == user_id)
        result = await self.session.exec(stmt)
        return result.one_or_none()

    async def create(self, user: User) -> User:
        """Create a new user"""
        self.session.add(user)
        await self.session.flush()
        await self.session.refresh(user)
        return user

    async def update(self, user: User) -> User:
        """Update existing user"""
        self.session.add(user)
        await self.session.flush()
        await self.session.refresh(user)
        return user

    async def get_by_verification_token(self, token: str) -> Optional[User]:
        """Get user by email verification token"""
        stmt = select(User).where(User.email_verification_token == token)
        result = await self.session.exec(stmt)
        return result.one_or_none()
