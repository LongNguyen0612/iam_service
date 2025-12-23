from dataclasses import dataclass
from typing import Generic, Optional, TypeVar

T = TypeVar("T")

@dataclass
class Error:
    code: str
    message: str
    reason: Optional[str] = None

class Result(Generic[T]):
    def __init__(self, value=None, error=None):
        self._value = value
        self._error = error

    def is_ok(self) -> bool:
        return self._error is None

    def is_err(self) -> bool:
        return self._error is not None

    @property
    def value(self) -> T:
        return self._value

    @property
    def error(self) -> Error:
        return self._error

class Return:
    @staticmethod
    def ok(value):
        return Result(value=value)

    @staticmethod
    def err(error):
        return Result(error=error)
