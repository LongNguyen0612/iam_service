from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field

from libs.result import Error
from src.api.error import ClientError, ServerError
from src.app.services.unit_of_work import UnitOfWork
from src.app.use_cases.tenants import (
    AcceptInvitationResponse,
    AcceptInvitationUseCase,
    ResendInvitationResponse,
    ResendInvitationUseCase,
    RevokeInvitationResponse,
    RevokeInvitationUseCase,
)
from src.depends import get_current_user, get_unit_of_work

router = APIRouter(prefix="/invitations", tags=["Invitations"])


class AcceptInvitationRequest(BaseModel):
    """
    Accept invitation HTTP request payload

    Validates incoming request for accepting an invitation.
    """

    token: str = Field(..., description="Invitation token")
    password: Optional[str] = Field(
        None, description="Password (required only for new users)"
    )


@router.post(
    "/accept",
    status_code=status.HTTP_200_OK,
    response_model=AcceptInvitationResponse,
)
async def accept_invitation(
    request: AcceptInvitationRequest,
    uow: UnitOfWork = Depends(get_unit_of_work),
):
    """
    Accept Invitation - AC-14.1, AC-14.2, AC-14.3, AC-14.4, AC-14.5

    Allows existing or new users to accept a tenant invitation.
    Existing users only need the token; new users must also provide a password.

    Raises:
        - 400 Bad Request: INVALID_TOKEN (AC-14.3), PASSWORD_REQUIRED,
                           INVALID_PASSWORD (AC-14.2)
        - 409 Conflict: INVITATION_ALREADY_ACCEPTED (AC-14.4), ALREADY_MEMBER
        - 410 Gone: INVITATION_EXPIRED (AC-14.3)
        - 500 Internal Server Error: Server error
    """
    # Execute use case
    use_case = AcceptInvitationUseCase(uow)
    result = await use_case.execute(request.token, request.password)

    # Handle errors
    if result.is_err():
        error = result.error
        if error.code in (
            "INVALID_TOKEN",
            "PASSWORD_REQUIRED",
            "INVALID_PASSWORD",
        ):
            raise ClientError(error, status_code=status.HTTP_400_BAD_REQUEST)
        elif error.code == "INVITATION_EXPIRED":
            raise ClientError(error, status_code=status.HTTP_410_GONE)
        elif error.code in ("INVITATION_ALREADY_ACCEPTED", "ALREADY_MEMBER"):
            raise ClientError(error, status_code=status.HTTP_409_CONFLICT)
        raise ServerError(error)

    # Return successful response
    return result.value


@router.post(
    "/{invitation_id}/resend",
    status_code=status.HTTP_200_OK,
    response_model=ResendInvitationResponse,
)
async def resend_invitation(
    invitation_id: str,
    current_user: dict = Depends(get_current_user),
    uow: UnitOfWork = Depends(get_unit_of_work),
):
    """
    Resend Invitation - AC-15.1, AC-15.3

    Resends a pending invitation with extended expiry (7 days from now).
    Only admin/owner can resend invitations.

    Raises:
        - 400 Bad Request: Invalid invitation_id format
        - 401 Unauthorized: Invalid or expired JWT
        - 403 Forbidden: INSUFFICIENT_ROLE (non-admin/owner)
        - 404 Not Found: INVITATION_NOT_FOUND
        - 409 Conflict: INVITATION_ALREADY_ACCEPTED (AC-15.3)
        - 500 Internal Server Error: Server error
    """
    # Extract user_id and tenant_id from JWT payload
    user_id = UUID(current_user["user_id"])
    tenant_id = UUID(current_user["tenant_id"])

    # Parse invitation ID
    try:
        invitation_uuid = UUID(invitation_id)
    except ValueError:
        raise ClientError(
            Error("INVALID_INVITATION_ID", "Invalid invitation ID format"),
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Execute use case
    use_case = ResendInvitationUseCase(uow)
    result = await use_case.execute(user_id, tenant_id, invitation_uuid)

    # Handle errors
    if result.is_err():
        error = result.error
        if error.code in ("NOT_A_MEMBER", "INSUFFICIENT_ROLE"):
            raise ClientError(error, status_code=status.HTTP_403_FORBIDDEN)
        elif error.code == "INVITATION_NOT_FOUND":
            raise ClientError(error, status_code=status.HTTP_404_NOT_FOUND)
        elif error.code == "INVITATION_ALREADY_ACCEPTED":
            raise ClientError(error, status_code=status.HTTP_409_CONFLICT)
        raise ServerError(error)

    # Return successful response
    return result.value


@router.delete(
    "/{invitation_id}",
    status_code=status.HTTP_200_OK,
    response_model=RevokeInvitationResponse,
)
async def revoke_invitation(
    invitation_id: str,
    current_user: dict = Depends(get_current_user),
    uow: UnitOfWork = Depends(get_unit_of_work),
):
    """
    Revoke Invitation - AC-15.2, AC-15.3

    Revokes a pending invitation by setting status to expired.
    Only admin/owner can revoke invitations.

    Raises:
        - 400 Bad Request: Invalid invitation_id format
        - 401 Unauthorized: Invalid or expired JWT
        - 403 Forbidden: INSUFFICIENT_ROLE (non-admin/owner)
        - 404 Not Found: INVITATION_NOT_FOUND
        - 409 Conflict: INVITATION_ALREADY_ACCEPTED (AC-15.3)
        - 500 Internal Server Error: Server error
    """
    # Extract user_id and tenant_id from JWT payload
    user_id = UUID(current_user["user_id"])
    tenant_id = UUID(current_user["tenant_id"])

    # Parse invitation ID
    try:
        invitation_uuid = UUID(invitation_id)
    except ValueError:
        raise ClientError(
            Error("INVALID_INVITATION_ID", "Invalid invitation ID format"),
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Execute use case
    use_case = RevokeInvitationUseCase(uow)
    result = await use_case.execute(user_id, tenant_id, invitation_uuid)

    # Handle errors
    if result.is_err():
        error = result.error
        if error.code in ("NOT_A_MEMBER", "INSUFFICIENT_ROLE"):
            raise ClientError(error, status_code=status.HTTP_403_FORBIDDEN)
        elif error.code == "INVITATION_NOT_FOUND":
            raise ClientError(error, status_code=status.HTTP_404_NOT_FOUND)
        elif error.code == "INVITATION_ALREADY_ACCEPTED":
            raise ClientError(error, status_code=status.HTTP_409_CONFLICT)
        raise ServerError(error)

    # Return successful response
    return result.value
