from uuid import UUID
from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, EmailStr, Field

from libs.result import Error
from src.api.error import ClientError, ServerError
from src.app.services.unit_of_work import UnitOfWork
from src.app.use_cases.tenants import (
    DeleteTenantResponse,
    DeleteTenantUseCase,
    InviteUserResponse,
    InviteUserUseCase,
    RemoveMemberResponse,
    RemoveMemberUseCase,
    SwitchTenantUseCase,
)
from src.app.use_cases.users import ChangeRoleUseCase
from src.depends import get_current_user, get_unit_of_work

router = APIRouter(prefix="/tenants", tags=["Tenant"])


class SwitchTenantRequest(BaseModel):
    """
    Switch tenant HTTP request payload

    Validates incoming request for switching active tenant.
    """

    tenant_id: str = Field(..., description="Target tenant ID to switch to")


class TenantInfoResponse(BaseModel):
    """Tenant information in response"""

    id: str
    name: str
    role: str


class SwitchTenantResponse(BaseModel):
    """
    Switch tenant HTTP response payload

    Returns new JWT token scoped to target tenant.
    """

    access_token: str
    tenant: TenantInfoResponse


@router.post(
    "/switch", status_code=status.HTTP_200_OK, response_model=SwitchTenantResponse
)
async def switch_tenant(
    request: SwitchTenantRequest,
    current_user: dict = Depends(get_current_user),
    uow: UnitOfWork = Depends(get_unit_of_work),
):
    """
    Switch Active Tenant - AC-5.1, AC-5.2, AC-5.3, AC-5.4

    Switches the user's active tenant context and returns a new JWT token
    scoped to the target tenant.

    Raises:
        - 400 Bad Request: Invalid tenant_id format
        - 401 Unauthorized: Invalid or expired JWT
        - 403 Forbidden: NOT_A_MEMBER (AC-5.2), MEMBERSHIP_REVOKED (AC-5.3),
                        or TENANT_SUSPENDED (AC-5.4)
        - 404 Not Found: Tenant not found
        - 500 Internal Server Error: Server error
    """
    # Extract user_id from JWT payload
    user_id = UUID(current_user["user_id"])

    # Parse target tenant ID
    try:
        target_tenant_id = UUID(request.tenant_id)
    except ValueError:
        raise ClientError(
            Error("INVALID_TENANT_ID", "Invalid tenant ID format"),
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Execute use case
    use_case = SwitchTenantUseCase(uow)
    result = await use_case.execute(user_id, target_tenant_id)

    # Handle errors
    if result.is_err():
        error = result.error
        if error.code in ("NOT_A_MEMBER", "MEMBERSHIP_REVOKED", "TENANT_SUSPENDED"):
            raise ClientError(error, status_code=status.HTTP_403_FORBIDDEN)
        elif error.code == "TENANT_NOT_FOUND":
            raise ClientError(error, status_code=status.HTTP_404_NOT_FOUND)
        raise ServerError(error)

    # Return successful response
    return result.value


class InviteUserRequest(BaseModel):
    """
    Invite user HTTP request payload

    Validates incoming request for inviting a user to a tenant.
    """

    email: EmailStr = Field(..., description="Email address to invite")
    role: str = Field(..., description="Role to assign (owner/admin/member/viewer)")


@router.post(
    "/{tenant_id}/invite",
    status_code=status.HTTP_201_CREATED,
    response_model=InviteUserResponse,
)
async def invite_user(
    tenant_id: str,
    request: InviteUserRequest,
    current_user: dict = Depends(get_current_user),
    uow: UnitOfWork = Depends(get_unit_of_work),
):
    """
    Invite User to Tenant - AC-6.1, AC-6.2, AC-6.3, AC-6.4, AC-6.5

    Invites a user to join a tenant with a specified role.
    Requires owner or admin permissions.

    Raises:
        - 400 Bad Request: Invalid tenant_id or role format (AC-6.5)
        - 401 Unauthorized: Invalid or expired JWT
        - 403 Forbidden: INSUFFICIENT_ROLE (AC-6.2)
        - 409 Conflict: INVITE_ALREADY_EXISTS (AC-6.3) or ALREADY_MEMBER (AC-6.4)
        - 500 Internal Server Error: Server error
    """
    # Extract inviter user_id from JWT payload
    inviter_user_id = UUID(current_user["user_id"])

    # Parse tenant ID
    try:
        tenant_uuid = UUID(tenant_id)
    except ValueError:
        raise ClientError(
            Error("INVALID_TENANT_ID", "Invalid tenant ID format"),
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Execute use case
    use_case = InviteUserUseCase(uow)
    result = await use_case.execute(
        inviter_user_id, tenant_uuid, request.email, request.role
    )

    # Handle errors
    if result.is_err():
        error = result.error
        if error.code == "INVALID_ROLE":
            raise ClientError(error, status_code=status.HTTP_400_BAD_REQUEST)
        elif error.code == "INSUFFICIENT_ROLE":
            raise ClientError(error, status_code=status.HTTP_403_FORBIDDEN)
        elif error.code in ("INVITE_ALREADY_EXISTS", "ALREADY_MEMBER"):
            raise ClientError(error, status_code=status.HTTP_409_CONFLICT)
        raise ServerError(error)

    # Return successful response
    return result.value


class ChangeRoleRequest(BaseModel):
    """
    Change role HTTP request payload

    Validates incoming request for changing a member's role.
    """

    role: str = Field(..., description="New role (owner/admin/member/viewer)")


class ChangeRoleResponse(BaseModel):
    """
    Change role HTTP response payload

    Returns updated membership information.
    """

    status: str
    membership: dict


@router.put(
    "/{tenant_id}/members/{user_id}",
    status_code=status.HTTP_200_OK,
    response_model=ChangeRoleResponse,
)
async def change_member_role(
    tenant_id: str,
    user_id: str,
    request: ChangeRoleRequest,
    current_user: dict = Depends(get_current_user),
    uow: UnitOfWork = Depends(get_unit_of_work),
):
    """
    Change Member Role - AC-7.1, AC-7.2, AC-7.3, AC-7.4

    Changes a member's role within a tenant.
    Requires owner permissions.

    Raises:
        - 400 Bad Request: Invalid tenant_id, user_id, or role format (AC-7.4)
        - 401 Unauthorized: Invalid or expired JWT
        - 403 Forbidden: INSUFFICIENT_ROLE (non-owner)
        - 404 Not Found: MEMBERSHIP_NOT_FOUND (AC-7.3)
        - 409 Conflict: CANNOT_DEMOTE_SELF (AC-7.2)
        - 500 Internal Server Error: Server error
    """
    # Extract owner user_id from JWT payload
    owner_user_id = UUID(current_user["user_id"])

    # Parse tenant ID
    try:
        tenant_uuid = UUID(tenant_id)
    except ValueError:
        raise ClientError(
            Error("INVALID_TENANT_ID", "Invalid tenant ID format"),
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Parse target user ID
    try:
        target_user_uuid = UUID(user_id)
    except ValueError:
        raise ClientError(
            Error("INVALID_USER_ID", "Invalid user ID format"),
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Execute use case
    use_case = ChangeRoleUseCase(uow)
    result = await use_case.execute(
        owner_user_id, tenant_uuid, target_user_uuid, request.role
    )

    # Handle errors
    if result.is_err():
        error = result.error
        if error.code in ("INVALID_ROLE", "INVALID_USER_ID", "INVALID_TENANT_ID"):
            raise ClientError(error, status_code=status.HTTP_400_BAD_REQUEST)
        elif error.code == "INSUFFICIENT_ROLE":
            raise ClientError(error, status_code=status.HTTP_403_FORBIDDEN)
        elif error.code == "MEMBERSHIP_NOT_FOUND":
            raise ClientError(error, status_code=status.HTTP_404_NOT_FOUND)
        elif error.code == "CANNOT_DEMOTE_SELF":
            raise ClientError(error, status_code=status.HTTP_409_CONFLICT)
        raise ServerError(error)

    # Return successful response
    return result.value


@router.delete(
    "/{tenant_id}/members/{user_id}",
    status_code=status.HTTP_200_OK,
    response_model=RemoveMemberResponse,
)
async def remove_member(
    tenant_id: str,
    user_id: str,
    current_user: dict = Depends(get_current_user),
    uow: UnitOfWork = Depends(get_unit_of_work),
):
    """
    Remove Member from Tenant - AC-16.1, AC-16.2, AC-16.3, AC-16.4

    Removes a member from a tenant by revoking their membership.
    Requires owner or admin permissions.

    Raises:
        - 400 Bad Request: Invalid tenant_id or user_id format
        - 401 Unauthorized: Invalid or expired JWT
        - 403 Forbidden: INSUFFICIENT_ROLE (AC-16.4)
        - 404 Not Found: MEMBERSHIP_NOT_FOUND
        - 409 Conflict: CANNOT_REMOVE_LAST_OWNER (AC-16.2)
        - 500 Internal Server Error: Server error
    """
    # Extract requester user_id from JWT payload
    requester_user_id = UUID(current_user["user_id"])

    # Parse tenant ID
    try:
        tenant_uuid = UUID(tenant_id)
    except ValueError:
        raise ClientError(
            Error("INVALID_TENANT_ID", "Invalid tenant ID format"),
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Parse target user ID
    try:
        target_user_uuid = UUID(user_id)
    except ValueError:
        raise ClientError(
            Error("INVALID_USER_ID", "Invalid user ID format"),
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Execute use case
    use_case = RemoveMemberUseCase(uow)
    result = await use_case.execute(requester_user_id, tenant_uuid, target_user_uuid)

    # Handle errors
    if result.is_err():
        error = result.error
        if error.code in ("INVALID_TENANT_ID", "INVALID_USER_ID"):
            raise ClientError(error, status_code=status.HTTP_400_BAD_REQUEST)
        elif error.code in ("NOT_A_MEMBER", "INSUFFICIENT_ROLE"):
            raise ClientError(error, status_code=status.HTTP_403_FORBIDDEN)
        elif error.code == "MEMBERSHIP_NOT_FOUND":
            raise ClientError(error, status_code=status.HTTP_404_NOT_FOUND)
        elif error.code == "CANNOT_REMOVE_LAST_OWNER":
            raise ClientError(error, status_code=status.HTTP_409_CONFLICT)
        raise ServerError(error)

    # Return successful response
    return result.value


class DeleteTenantRequest(BaseModel):
    """
    Delete tenant HTTP request payload

    Requires explicit confirmation string to prevent accidental deletion.
    """

    confirmation: str = Field(
        ...,
        description="Confirmation string (must match 'DELETE_TENANT_{tenant_name}')",
    )


@router.delete(
    "/{tenant_id}",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=DeleteTenantResponse,
)
async def delete_tenant(
    tenant_id: str,
    request: DeleteTenantRequest,
    current_user: dict = Depends(get_current_user),
    uow: UnitOfWork = Depends(get_unit_of_work),
):
    """
    Delete Tenant - AC-18.1, AC-18.4

    Initiates soft deletion of a tenant. Only the tenant owner can delete.
    Requires explicit confirmation string to prevent accidental deletion.
    All active sessions are revoked immediately.

    The tenant is marked for deletion with a 7-day rollback window.
    Actual data purge happens after the rollback period expires.

    Raises:
        - 400 Bad Request: Invalid tenant_id or confirmation string (AC-18.1)
        - 401 Unauthorized: Invalid or expired JWT
        - 402 Payment Required: Unpaid balance exists (AC-18.4) [future]
        - 403 Forbidden: INSUFFICIENT_ROLE (only owner can delete)
        - 404 Not Found: Tenant not found
        - 409 Conflict: ALREADY_DELETED (tenant already scheduled for deletion)
        - 500 Internal Server Error: Server error
    """
    # Extract user_id from JWT payload
    user_id = UUID(current_user["user_id"])

    # Parse tenant ID
    try:
        tenant_uuid = UUID(tenant_id)
    except ValueError:
        raise ClientError(
            Error("INVALID_TENANT_ID", "Invalid tenant ID format"),
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Execute use case
    use_case = DeleteTenantUseCase(uow)
    result = await use_case.execute(user_id, tenant_uuid, request.confirmation)

    # Handle errors
    if result.is_err():
        error = result.error
        if error.code in ("INVALID_TENANT_ID", "INVALID_CONFIRMATION"):
            raise ClientError(error, status_code=status.HTTP_400_BAD_REQUEST)
        elif error.code == "PAYMENT_REQUIRED":
            raise ClientError(error, status_code=status.HTTP_402_PAYMENT_REQUIRED)
        elif error.code == "INSUFFICIENT_ROLE":
            raise ClientError(error, status_code=status.HTTP_403_FORBIDDEN)
        elif error.code == "TENANT_NOT_FOUND":
            raise ClientError(error, status_code=status.HTTP_404_NOT_FOUND)
        elif error.code == "ALREADY_DELETED":
            raise ClientError(error, status_code=status.HTTP_409_CONFLICT)
        raise ServerError(error)

    # Return successful response (202 Accepted for async operation)
    return result.value
