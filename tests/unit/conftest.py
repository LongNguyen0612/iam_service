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
