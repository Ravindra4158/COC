from datetime import datetime, timezone
from threading import Lock
from typing import Any

from src.pipeline import run_analysis

_cache: dict[str, Any] = {
    "result": None,
    "timestamp": None,
    "disabled_vulnerabilities": [],
    "seed": None,
}
_lock = Lock()


def get_analysis(
    force: bool = False,
    disabled_vulnerabilities: list[str] | None = None,
    seed: int | None = None,
) -> dict[str, Any]:
    with _lock:
        state_changed = False
        if disabled_vulnerabilities is not None and sorted(disabled_vulnerabilities) != sorted(_cache.get("disabled_vulnerabilities", [])):
            _cache["disabled_vulnerabilities"] = list(disabled_vulnerabilities)
            state_changed = True
        if seed is not None and seed != _cache.get("seed"):
            _cache["seed"] = seed
            state_changed = True

        if force or state_changed or _cache["result"] is None:
            _cache["result"] = run_analysis(
                disabled_vulnerabilities=_cache.get("disabled_vulnerabilities", []),
                seed=_cache.get("seed"),
            )
            _cache["timestamp"] = datetime.now(timezone.utc).isoformat()
        return _cache["result"]


def cache_timestamp() -> str | None:
    return _cache["timestamp"]


def get_active_patches() -> list[str]:
    return list(_cache.get("disabled_vulnerabilities", []))


def get_active_seed() -> int | None:
    return _cache.get("seed")


def reset_state() -> None:
    with _lock:
        _cache["disabled_vulnerabilities"] = []
        _cache["seed"] = None
        _cache["result"] = None
        _cache["timestamp"] = None
