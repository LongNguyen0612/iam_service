from typing import List, Optional
from uuid import UUID

from sqlmodel import select, update
from sqlmodel.ext.asyncio.session import AsyncSession

from src.app.repositories.session_repository import ISessionRepository
from src.domain.entities import Session


class SessionRepository(ISessionRepository):
    """Session repository implementation using SQLModel"""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_by_id(self, session_id: UUID) -> Optional[Session]:
        """Get session by ID"""
        stmt = select(Session).where(Session.id == session_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_user_id(self, user_id: UUID) -> List[Session]:
        """Get all sessions for a user"""
        stmt = select(Session).where(Session.user_id == user_id)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def create(self, session_obj: Session) -> Session:
        """Create a new session"""
        self.session.add(session_obj)
        await self.session.flush()
        await self.session.refresh(session_obj)
        return session_obj

    async def update(self, session_obj: Session) -> Session:
        """Update existing session"""
        self.session.add(session_obj)
        await self.session.flush()
        await self.session.refresh(session_obj)
        return session_obj

    async def find_by_refresh_token(self, refresh_token: str) -> Optional[Session]:
        """
        Find session by verifying refresh token hash.

        NOTE: This scans all sessions and verifies bcrypt hashes.
        For production with many sessions, consider adding:
        1. A searchable token_id (SHA-256 hash) for O(1) lookup
        2. Filtering by created_at to limit candidates
        3. Caching frequently accessed sessions

        We don't filter by revoked/expired here - that's checked in the use case
        so we can return appropriate error messages.
        """
        import bcrypt

        # Get all sessions (we check revoked/expired in use case for better error messages)
        # In production, add index on created_at and limit to recent sessions
        stmt = select(Session)
        result = await self.session.execute(stmt)
        sessions = list(result.scalars().all())

        # Verify token hash for each candidate session
        refresh_token_bytes = refresh_token.encode()
        for session_obj in sessions:
            try:
                if bcrypt.checkpw(refresh_token_bytes, session_obj.refresh_token_hash.encode()):
                    return session_obj
            except (ValueError, AttributeError):
                # Skip sessions with invalid hashes
                continue

        return None

    async def revoke_all_by_user_id(self, user_id: UUID) -> int:
        """Revoke all active sessions for a user"""
        stmt = (
            update(Session)
            .where(Session.user_id == user_id, Session.revoked == False)
            .values(revoked=True)
        )
        result = await self.session.execute(stmt)
        await self.session.flush()
        return result.rowcount

    async def revoke_all_except_session(self, user_id: UUID, session_id: UUID) -> int:
        """Revoke all sessions for a user except the specified session"""
        stmt = (
            update(Session)
            .where(
                Session.user_id == user_id,
                Session.id != session_id,
                Session.revoked == False,
            )
            .values(revoked=True)
        )
        result = await self.session.execute(stmt)
        await self.session.flush()
        return result.rowcount

    async def revoke_by_id(self, session_id: UUID) -> bool:
        """Revoke a specific session by ID"""
        stmt = (
            update(Session)
            .where(Session.id == session_id, Session.revoked == False)
            .values(revoked=True)
        )
        result = await self.session.execute(stmt)
        await self.session.flush()
        return result.rowcount > 0

    async def get_active_by_tenant_id(self, tenant_id: UUID) -> List[Session]:
        """Get all active (non-revoked) sessions for a tenant"""
        stmt = select(Session).where(
            Session.tenant_id == tenant_id,
            Session.revoked == False
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_user_and_tenant(
        self, user_id: UUID, tenant_id: UUID
    ) -> List[Session]:
        """Get all sessions for a user in a specific tenant"""
        stmt = select(Session).where(
            Session.user_id == user_id, Session.tenant_id == tenant_id
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
