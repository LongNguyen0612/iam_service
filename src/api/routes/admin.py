"""
Admin API Routes - System Administration Endpoints

These endpoints are for internal service integrations (e.g., billing system).
Authentication is via Admin API Key, not user JWTs.
"""

from uuid import UUID
from fastapi import APIRouter, Depends, status

from libs.result import Error
from src.api.error import ClientError, ServerError
from src.api.utils.admin_auth import verify_admin_api_key
from src.app.services.unit_of_work import UnitOfWork
from src.app.use_cases.admin import (
    CancelTenantDeletionResponse,
    CancelTenantDeletionUseCase,
    RestoreTenantResponse,
    RestoreTenantUseCase,
    SuspendTenantResponse,
    SuspendTenantUseCase,
)
from src.depends import get_unit_of_work

router = APIRouter(prefix="/admin", tags=["Admin"])


@router.post(
    "/tenants/{tenant_id}/suspend",
    status_code=status.HTTP_200_OK,
    response_model=SuspendTenantResponse,
    dependencies=[Depends(verify_admin_api_key)],
)
async def suspend_tenant(
    tenant_id: UUID,
    uow: UnitOfWork = Depends(get_unit_of_work),
):
    """
    Suspend Tenant - AC-17.1

    Billing system endpoint to suspend a tenant for non-payment.
    Revokes all active sessions and blocks tenant operations.

    Requires: X-Admin-API-Key header

    Raises:
        - 401 Unauthorized: Missing or invalid admin API key
        - 404 Not Found: TENANT_NOT_FOUND
        - 500 Internal Server Error: Server error
    """
    use_case = SuspendTenantUseCase(uow)
    result = await use_case.execute(tenant_id)

    if result.is_err():
        error = result.error
        if error.code == "TENANT_NOT_FOUND":
            raise ClientError(error, status_code=status.HTTP_404_NOT_FOUND)
        raise ServerError(error)

    return result.value


@router.post(
    "/tenants/{tenant_id}/restore",
    status_code=status.HTTP_200_OK,
    response_model=RestoreTenantResponse,
    dependencies=[Depends(verify_admin_api_key)],
)
async def restore_tenant(
    tenant_id: UUID,
    uow: UnitOfWork = Depends(get_unit_of_work),
):
    """
    Restore Tenant - AC-17.2

    Billing system endpoint to restore a suspended tenant after payment.
    Allows users to log in and access tenant resources again.

    Requires: X-Admin-API-Key header

    Raises:
        - 401 Unauthorized: Missing or invalid admin API key
        - 404 Not Found: TENANT_NOT_FOUND
        - 500 Internal Server Error: Server error
    """
    use_case = RestoreTenantUseCase(uow)
    result = await use_case.execute(tenant_id)

    if result.is_err():
        error = result.error
        if error.code == "TENANT_NOT_FOUND":
            raise ClientError(error, status_code=status.HTTP_404_NOT_FOUND)
        raise ServerError(error)

    return result.value


@router.post(
    "/tenants/{tenant_id}/cancel-deletion",
    status_code=status.HTTP_200_OK,
    response_model=CancelTenantDeletionResponse,
    dependencies=[Depends(verify_admin_api_key)],
)
async def cancel_tenant_deletion(
    tenant_id: UUID,
    uow: UnitOfWork = Depends(get_unit_of_work),
):
    """
    Cancel Tenant Deletion - AC-18.3

    Admin/support endpoint to cancel tenant deletion within 7-day rollback window.
    Restores tenant to active status.

    Requires: X-Admin-API-Key header

    Raises:
        - 401 Unauthorized: Missing or invalid admin API key
        - 404 Not Found: TENANT_NOT_FOUND
        - 400 Bad Request: NOT_SCHEDULED_FOR_DELETION
        - 410 Gone: ROLLBACK_WINDOW_EXPIRED
        - 500 Internal Server Error: Server error
    """
    use_case = CancelTenantDeletionUseCase(uow)
    result = await use_case.execute(tenant_id)

    if result.is_err():
        error = result.error
        if error.code == "TENANT_NOT_FOUND":
            raise ClientError(error, status_code=status.HTTP_404_NOT_FOUND)
        elif error.code == "NOT_SCHEDULED_FOR_DELETION":
            raise ClientError(error, status_code=status.HTTP_400_BAD_REQUEST)
        elif error.code == "ROLLBACK_WINDOW_EXPIRED":
            raise ClientError(error, status_code=status.HTTP_410_GONE)
        raise ServerError(error)

    return result.value
