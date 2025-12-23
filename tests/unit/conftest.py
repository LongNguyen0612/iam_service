import pytest
from unittest.mock import AsyncMock, MagicMock


@pytest.fixture
def mock_uow():
    uow = MagicMock()
    uow.__aenter__ = AsyncMock(return_value=uow)
    uow.__aexit__ = AsyncMock(return_value=False)  # Must return False to not suppress exceptions
    uow.commit = AsyncMock()
    uow.rollback = AsyncMock()
    return uow


@pytest.fixture
def mock_audit_service():
    """Mock AuditService for use cases that require audit logging"""
    audit_service = MagicMock()
    audit_service.log_event = AsyncMock()
    audit_service.get_by_tenant_paginated = AsyncMock(return_value=([], None))
    return audit_service
