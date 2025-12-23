from uuid import UUID
from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field

from src.api.error import ClientError, ServerError
from src.app.services.unit_of_work import UnitOfWork
from src.app.use_cases.users import RevokeSessionsUseCase
from src.depends import get_current_user, get_unit_of_work

router = APIRouter(prefix="/sessions", tags=["Sessions"])


class RevokeAllSessionsRequest(BaseModel):
    """Request to revoke all sessions for a user"""

    user_id: str = Field(..., description="User ID whose sessions will be revoked")


class RevokeSessionResponse(BaseModel):
    """Response for session revocation operations"""

    message: str
    revoked_count: int


class RevokeSpecificSessionResponse(BaseModel):
    """Response for specific session revocation"""

    message: str
    session_id: str
    revoked: bool


@router.post(
    "/revoke-all",
    status_code=status.HTTP_200_OK,
    response_model=RevokeSessionResponse,
)
async def revoke_all_sessions(
    request: RevokeAllSessionsRequest,
    current_user: dict = Depends(get_current_user),
    uow: UnitOfWork = Depends(get_unit_of_work),
):
    """
    Revoke All Sessions - IAM-008

    Revokes all active sessions for a user. Useful for:
    - Security incidents (account compromise)
    - Password changes
    - Admin-initiated logout

    Authorization:
    - Users can revoke their own sessions
    - Admins/owners can revoke any user's sessions within their tenant

    Raises:
        - 403 Forbidden: Insufficient permissions
        - 404 Not Found: User not found
        - 500 Internal Server Error: Server error
    """
    target_user_id = UUID(request.user_id)
    requesting_user_id = UUID(current_user["user_id"])
    requesting_tenant_id = UUID(current_user["tenant_id"])
    requesting_role = current_user["role"]

    use_case = RevokeSessionsUseCase(uow)
    result = await use_case.revoke_all_sessions(
        target_user_id,
        requesting_user_id,
        requesting_tenant_id,
        requesting_role,
    )

    if result.is_err():
        error = result.error
        if error.code == "FORBIDDEN":
            raise ClientError(error, status_code=status.HTTP_403_FORBIDDEN)
        elif error.code == "USER_NOT_FOUND":
            raise ClientError(error, status_code=status.HTTP_404_NOT_FOUND)
        raise ServerError(error)

    data = result.value
    return {
        "message": f"Successfully revoked {data['revoked_count']} session(s)",
        "revoked_count": data["revoked_count"],
    }


@router.delete(
    "/{session_id}",
    status_code=status.HTTP_200_OK,
    response_model=RevokeSpecificSessionResponse,
)
async def revoke_specific_session(
    session_id: str,
    current_user: dict = Depends(get_current_user),
    uow: UnitOfWork = Depends(get_unit_of_work),
):
    """
    Revoke Specific Session - IAM-008

    Revokes a single session by ID. Useful for:
    - Managing individual devices/sessions
    - Logging out from specific devices

    Authorization:
    - Users can revoke their own sessions
    - Admins/owners can revoke any user's sessions within their tenant

    Raises:
        - 403 Forbidden: Insufficient permissions
        - 404 Not Found: Session not found
        - 409 Conflict: Session already revoked
        - 500 Internal Server Error: Server error
    """
    session_uuid = UUID(session_id)
    requesting_user_id = UUID(current_user["user_id"])
    requesting_tenant_id = UUID(current_user["tenant_id"])
    requesting_role = current_user["role"]

    use_case = RevokeSessionsUseCase(uow)
    result = await use_case.revoke_specific_session(
        session_uuid,
        requesting_user_id,
        requesting_tenant_id,
        requesting_role,
    )

    if result.is_err():
        error = result.error
        if error.code == "FORBIDDEN":
            raise ClientError(error, status_code=status.HTTP_403_FORBIDDEN)
        elif error.code == "SESSION_NOT_FOUND":
            raise ClientError(error, status_code=status.HTTP_404_NOT_FOUND)
        elif error.code == "SESSION_ALREADY_REVOKED":
            raise ClientError(error, status_code=status.HTTP_409_CONFLICT)
        raise ServerError(error)

    data = result.value
    return {
        "message": "Session revoked successfully",
        "session_id": data["session_id"],
        "revoked": data["revoked"],
    }


class RevokeOthersRequest(BaseModel):
    """Request to revoke all sessions except the current one"""

    current_session_id: str = Field(
        ..., description="Current session ID to keep active (from login/refresh response)"
    )


@router.post(
    "/revoke-others",
    status_code=status.HTTP_200_OK,
    response_model=RevokeSessionResponse,
)
async def revoke_all_except_current(
    request: RevokeOthersRequest,
    current_user: dict = Depends(get_current_user),
    uow: UnitOfWork = Depends(get_unit_of_work),
):
    """
    Revoke All Other Sessions - IAM-008

    Revokes all sessions except the current one (logout other devices).
    Common security feature for users to manage their active sessions.

    The client must provide the current_session_id (received during login/refresh).

    Raises:
        - 403 Forbidden: Session doesn't belong to user
        - 404 Not Found: Current session not found
        - 500 Internal Server Error: Server error
    """
    current_session_id = UUID(request.current_session_id)
    requesting_user_id = UUID(current_user["user_id"])
    requesting_tenant_id = UUID(current_user["tenant_id"])

    use_case = RevokeSessionsUseCase(uow)
    result = await use_case.revoke_all_except_current(
        current_session_id,
        requesting_user_id,
        requesting_tenant_id,
    )

    if result.is_err():
        error = result.error
        if error.code == "FORBIDDEN":
            raise ClientError(error, status_code=status.HTTP_403_FORBIDDEN)
        elif error.code == "SESSION_NOT_FOUND":
            raise ClientError(error, status_code=status.HTTP_404_NOT_FOUND)
        raise ServerError(error)

    data = result.value
    return {
        "message": f"Successfully revoked {data['revoked_count']} other session(s)",
        "revoked_count": data["revoked_count"],
    }
