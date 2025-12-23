import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID
from datetime import datetime, UTC

# Add monorepo root to Python path for libs access
monorepo_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(monorepo_root))

import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession
from tests.fixtures.json_loader import TestDataLoader
from src.depends import get_unit_of_work, get_audit_service
from src.adapter.services.unit_of_work import SqlAlchemyUnitOfWork
from src.app.services.audit_service import IAuditService


class InMemoryAuditService(IAuditService):
    """In-memory audit service for testing"""

    def __init__(self):
        self.events: List[Dict[str, Any]] = []

    async def log_event(
        self,
        action: str,
        tenant_id: Optional[UUID],
        user_id: Optional[UUID],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.events.append({
            "action": action,
            "tenant_id": str(tenant_id) if tenant_id else None,
            "user_id": str(user_id) if user_id else None,
            "event_metadata": metadata or {},
            "created_at": datetime.now(UTC),
        })

    async def get_by_tenant_paginated(
        self,
        tenant_id: UUID,
        limit: int = 50,
        cursor: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        tenant_events = [
            e for e in self.events
            if e.get("tenant_id") == str(tenant_id)
        ]
        # Sort by created_at DESC
        tenant_events.sort(key=lambda x: x["created_at"], reverse=True)
        return tenant_events[:limit], None


# Shared in-memory audit service instance for all tests
_test_audit_service = InMemoryAuditService()


@pytest_asyncio.fixture
def test_data():
    return TestDataLoader()


@pytest_asyncio.fixture
async def engine():
    # Use PostgreSQL for tests to match production
    import sqlalchemy
    engine = create_async_engine(
        "postgresql+asyncpg://postgres:postgres@localhost:5432/iam_service_test",
        echo=False
    )

    # Drop and recreate schema for clean state
    async with engine.begin() as conn:
        await conn.execute(sqlalchemy.text("DROP SCHEMA IF EXISTS public CASCADE"))
        await conn.execute(sqlalchemy.text("CREATE SCHEMA public"))
        await conn.run_sync(SQLModel.metadata.create_all)

    yield engine

    # Cleanup
    async with engine.begin() as conn:
        await conn.execute(sqlalchemy.text("DROP SCHEMA IF EXISTS public CASCADE"))
        await conn.execute(sqlalchemy.text("CREATE SCHEMA public"))

    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(engine):
    Session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with Session() as session:
        yield session


@pytest_asyncio.fixture
async def audit_service():
    """Provide fresh in-memory audit service for each test"""
    service = InMemoryAuditService()
    return service


@pytest_asyncio.fixture
async def client(db_session, audit_service):
    from httpx import ASGITransport
    from src.api.app import create_app
    from config import ApplicationConfig

    app = create_app(ApplicationConfig)

    async def override_get_unit_of_work():
        yield SqlAlchemyUnitOfWork(db_session)

    def override_get_audit_service():
        return audit_service

    app.dependency_overrides[get_unit_of_work] = override_get_unit_of_work
    app.dependency_overrides[get_audit_service] = override_get_audit_service

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
