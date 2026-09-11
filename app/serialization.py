from typing import Any

import pandas as pd


def frame_records(frame: pd.DataFrame, columns: list[str] | None = None) -> list[dict[str, Any]]:
    if frame.empty:
        return []
    selected = frame if columns is None else frame.reindex(columns=[column for column in columns if column in frame.columns])
    records = selected.to_dict("records")
    return [_clean(record) for record in records]


def _clean(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _clean(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_clean(item) for item in value]
    if hasattr(value, "item"):
        return _clean(value.item())
    if pd.isna(value) if not isinstance(value, (dict, list, tuple, set)) else False:
        return None
    return value
