from uuid import UUID
from fastapi import APIRouter, Depends, status
from pydantic import BaseModel

from src.api.error import ClientError, ServerError
from src.app.services.unit_of_work import UnitOfWork
from src.app.use_cases.users import LoadContextUseCase
from src.depends import get_current_user, get_unit_of_work

router = APIRouter(tags=["User"])


class UserResponse(BaseModel):
    """User details in response"""
    id: str
    email: str
    email_verified: bool


class TenantContextResponse(BaseModel):
    """Tenant context in response"""
    id: str
    name: str
    role: str
    status: str


class MeResponse(BaseModel):
    """GET /me response payload"""
    user: UserResponse
    tenant: TenantContextResponse


@router.get("/me", status_code=status.HTTP_200_OK, response_model=MeResponse)
async def get_me(
    current_user: dict = Depends(get_current_user),
    uow: UnitOfWork = Depends(get_unit_of_work),
):
    """
    Load Current User & Tenant Context - AC-4.1, AC-4.2, AC-4.3, AC-4.4

    Returns current user information and tenant context based on JWT token.

    Raises:
        - 401 Unauthorized: Invalid or expired JWT (AC-4.2)
        - 403 Forbidden: Membership revoked (AC-4.3) or tenant suspended (AC-4.4)
        - 500 Internal Server Error: Server error
    """
    # Extract claims from JWT payload
    user_id = UUID(current_user["user_id"])
    tenant_id = UUID(current_user["tenant_id"])
    role = current_user["role"]

    # Execute use case
    use_case = LoadContextUseCase(uow)
    result = await use_case.execute(user_id, tenant_id, role)

    # Handle errors
    if result.is_err():
        error = result.error
        if error.code in ("MEMBERSHIP_REVOKED", "TENANT_SUSPENDED"):
            raise ClientError(error, status_code=status.HTTP_403_FORBIDDEN)
        raise ServerError(error)

    # Return successful response
    return result.value
