from datetime import datetime, timezone
from threading import Lock
from typing import Any

from src.pipeline import run_analysis

_cache: dict[str, Any] = {"result": None, "timestamp": None}
_lock = Lock()


def get_analysis(force: bool = False) -> dict[str, Any]:
    with _lock:
        if force or _cache["result"] is None:
            _cache["result"] = run_analysis()
            _cache["timestamp"] = datetime.now(timezone.utc).isoformat()
        return _cache["result"]


def cache_timestamp() -> str | None:
    return _cache["timestamp"]
