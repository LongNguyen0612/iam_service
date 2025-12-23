from typing import Dict, Set


def exclude_keys(data: Dict, keys: Set[str]) -> Dict:
    return {k: v for k, v in data.items() if k not in keys}
