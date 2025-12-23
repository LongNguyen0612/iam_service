import sys
from pathlib import Path

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
from src.depends import get_unit_of_work
from src.adapter.services.unit_of_work import SqlAlchemyUnitOfWork


@pytest_asyncio.fixture
def test_data():
    return TestDataLoader()


@pytest_asyncio.fixture
async def engine():
    engine = create_async_engine("sqlite+aiosqlite:///./test.db")
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(engine):
    Session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with Session() as session:
        yield session


@pytest_asyncio.fixture
async def client(db_session):
    from httpx import ASGITransport
    from src.api.app import create_app
    from config import ApplicationConfig

    app = create_app(ApplicationConfig)

    async def override_get_unit_of_work():
        yield SqlAlchemyUnitOfWork(db_session)

    app.dependency_overrides[get_unit_of_work] = override_get_unit_of_work

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
