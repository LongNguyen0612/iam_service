from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel.ext.asyncio.session import AsyncSession
from config import ApplicationConfig
from src.adapter.services.unit_of_work import SqlAlchemyUnitOfWork
from src.api.utils.jwt import verify_jwt

engine = create_async_engine(ApplicationConfig.DB_URI, echo=False, future=True)

AsyncSessionLocal = sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
)

security = HTTPBearer()


async def get_session() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session


async def get_unit_of_work():
    async with AsyncSessionLocal() as session:
        yield SqlAlchemyUnitOfWork(session)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    """
    Dependency to extract and verify JWT token from Authorization header.

    Args:
        credentials: Bearer token from Authorization header

    Returns:
        Decoded JWT payload containing user_id, tenant_id, role

    Raises:
        HTTPException: 401 if token is invalid or expired
    """
    token = credentials.credentials
    payload = verify_jwt(token)

    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    return payload
