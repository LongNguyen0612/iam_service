"""Data Transfer Objects for Admin Use Cases

Pydantic models for admin-related command inputs and response outputs.
"""

from decimal import Decimal
from pydantic import BaseModel, Field


class TenantOverviewResponseDTO(BaseModel):
    """
    Response DTO for Admin Views Tenant Overview (UC-41)

    Aggregates tenant information from IAM and Billing services.
    """

    tenant_id: str = Field(
        ...,
        description="Tenant identifier"
    )

    plan: str = Field(
        ...,
        description="Current subscription plan name"
    )

    credit_balance: Decimal = Field(
        ...,
        description="Current credit balance from billing service"
    )

    status: str = Field(
        ...,
        description="Tenant operational status (active, suspended)"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "tenant_id": "t1",
                "plan": "pro",
                "credit_balance": "120.500000",
                "status": "active"
            }
        }
