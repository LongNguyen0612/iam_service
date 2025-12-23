import copy
import json
from pathlib import Path
from typing import Any, Dict


class TestDataLoader:
    _data: Dict[str, Any] = None

    @classmethod
    def load(cls) -> Dict[str, Any]:
        if cls._data is None:
            with open(Path(__file__).parent / "test_data.json") as f:
                cls._data = json.load(f)
        return cls._data

    @classmethod
    def get(cls, key: str) -> Any:
        return cls.load().get(key)

    @classmethod
    def get_copy(cls, key: str) -> Any:
        return copy.deepcopy(cls.get(key))
