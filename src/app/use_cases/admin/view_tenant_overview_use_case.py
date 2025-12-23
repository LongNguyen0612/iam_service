"""
Use Case: View Tenant Overview (UC-41)

Admin views consolidated overview of tenant including subscription,
credit balance, and operational status.
"""

from decimal import Decimal
from uuid import UUID

import httpx

from libs.result import Error, Result, Return
from src.app.services.unit_of_work import UnitOfWork
from config import ApplicationConfig

from .dtos import TenantOverviewResponseDTO


class ViewTenantOverviewUseCase:
    """
    View consolidated tenant overview for admin.

    Business Logic:
    1. Validate tenant exists in IAM
    2. Get subscription plan from billing service
    3. Get credit balance from billing service
    4. Return aggregated tenant overview

    External Dependencies:
    - Billing Service: GET /billing/credits/balance/{tenant_id}
    - Billing Service: subscription info (currently simulated from balance endpoint)
    """

    def __init__(self, uow: UnitOfWork):
        self.uow = uow
        self.billing_service_url = getattr(
            ApplicationConfig, "BILLING_SERVICE_URL", "http://billing_api:8000"
        )

    async def execute(self, tenant_id: UUID) -> Result[TenantOverviewResponseDTO]:
        """
        Execute view tenant overview use case.

        Args:
            tenant_id: UUID of tenant to view

        Returns:
            Result[TenantOverviewResponseDTO] with aggregated tenant data
        """
        async with self.uow:
            # 1. Validate tenant exists in IAM
            tenant = await self.uow.tenants.get_by_id(tenant_id)
            if not tenant:
                return Return.err(
                    Error("TENANT_NOT_FOUND", "Tenant not found")
                )

            # 2. Get credit balance and subscription from billing service
            tenant_id_str = str(tenant_id)
            credit_balance = await self._get_credit_balance(tenant_id_str)
            plan = await self._get_subscription_plan(tenant_id_str)

            # 3. Return aggregated overview
            return Return.ok(
                TenantOverviewResponseDTO(
                    tenant_id=tenant_id_str,
                    plan=plan,
                    credit_balance=credit_balance,
                    status=tenant.status.value,
                )
            )

    async def _get_credit_balance(self, tenant_id: str) -> Decimal:
        """
        Get credit balance from billing service.

        Handles billing service unavailability gracefully by returning 0.

        Args:
            tenant_id: Tenant identifier string

        Returns:
            Current credit balance or Decimal("0") if unavailable
        """
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    f"{self.billing_service_url}/billing/credits/balance/{tenant_id}"
                )

                if response.status_code == 200:
                    data = response.json()
                    return Decimal(str(data.get("balance", "0")))
                elif response.status_code == 404:
                    # Tenant has no ledger yet - return 0
                    return Decimal("0")
                else:
                    # Billing service error - return 0 gracefully
                    return Decimal("0")

        except httpx.RequestError:
            # Network error or billing service unavailable
            return Decimal("0")

    async def _get_subscription_plan(self, tenant_id: str) -> str:
        """
        Get subscription plan from billing service.

        Currently billing service does not expose subscription endpoint,
        so we return a placeholder. In production, this would call:
        GET /billing/subscriptions/{tenant_id}

        Args:
            tenant_id: Tenant identifier string

        Returns:
            Plan name or "unknown" if unavailable
        """
        # TODO: When billing service exposes subscription endpoint, call it here
        # For now, attempt to infer from internal billing API if available
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                # Try internal subscription endpoint if it exists
                response = await client.get(
                    f"{self.billing_service_url}/billing/subscriptions/{tenant_id}"
                )

                if response.status_code == 200:
                    data = response.json()
                    return data.get("plan_name", "unknown")

        except httpx.RequestError:
            pass

        # Default to "unknown" if subscription info unavailable
        return "unknown"
