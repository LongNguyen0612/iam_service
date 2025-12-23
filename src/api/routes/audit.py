"""
Audit API Routes

Handles audit event retrieval endpoints.
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel

from src.api.error import ClientError, ServerError
from src.app.services.unit_of_work import UnitOfWork
from src.app.use_cases.audit import GetAuditEventsUseCase
from src.depends import get_current_user, get_unit_of_work

router = APIRouter(prefix="/audit", tags=["Audit"])


class AuditEventResponse(BaseModel):
    """Single audit event in response"""

    action: str
    user_email: Optional[str]
    timestamp: str
    metadata: Dict[str, Any]


class AuditEventsResponse(BaseModel):
    """GET /audit/auth-events response payload"""

    events: List[AuditEventResponse]
    next_cursor: Optional[str]


@router.get(
    "/auth-events",
    status_code=status.HTTP_200_OK,
    response_model=AuditEventsResponse,
)
async def get_auth_events(
    current_user: dict = Depends(get_current_user),
    uow: UnitOfWork = Depends(get_unit_of_work),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of events to return"),
    cursor: Optional[str] = Query(None, description="Pagination cursor"),
):
    """
    Get Authentication Audit Events - AC-9.1, AC-9.2

    Returns authentication-related audit logs for the tenant.
    Only accessible by admin and owner roles.

    Query Parameters:
        - limit: Maximum number of events to return (1-100, default 50)
        - cursor: Pagination cursor for fetching next page

    Returns:
        - events: List of audit events ordered by newest first
        - next_cursor: Cursor for next page (null if no more events)

    Raises:
        - 401 Unauthorized: Invalid or expired JWT
        - 403 Forbidden: Insufficient role (must be admin/owner) (AC-9.2)
        - 403 Forbidden: Membership revoked or tenant suspended
        - 500 Internal Server Error: Server error
    """
    # Extract claims from JWT payload
    user_id = UUID(current_user["user_id"])
    tenant_id = UUID(current_user["tenant_id"])
    role = current_user["role"]

    # Execute use case
    use_case = GetAuditEventsUseCase(uow)
    result = await use_case.execute(
        user_id=user_id,
        tenant_id=tenant_id,
        role=role,
        limit=limit,
        cursor=cursor,
    )

    # Handle errors
    if result.is_err():
        error = result.error
        if error.code == "INSUFFICIENT_ROLE":
            raise ClientError(error, status_code=status.HTTP_403_FORBIDDEN)
        if error.code in ("MEMBERSHIP_REVOKED", "TENANT_SUSPENDED"):
            raise ClientError(error, status_code=status.HTTP_403_FORBIDDEN)
        raise ServerError(error)

    # Return successful response
    return result.value
