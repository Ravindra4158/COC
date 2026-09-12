from pathlib import Path
from typing import Any

import pandas as pd


def rank_patch_candidates(results: Any) -> pd.DataFrame:
    """Rank patch candidates by measured risk reduction with deterministic ties."""
    frame = results.copy() if isinstance(results, pd.DataFrame) else pd.DataFrame(results)
    if frame.empty:
        if "rank" not in frame.columns:
            frame.insert(0, "rank", pd.Series(dtype="int64"))
        return frame
    for column in ("patch_value", "risk_reduction_percent", "priority_score", "cvss"):
        if column not in frame:
            frame[column] = 0.0
    frame = frame.sort_values(
        ["patch_value", "risk_reduction_percent", "priority_score", "cvss", "host_id", "vulnerability_id"],
        ascending=[False, False, False, False, True, True],
        kind="mergesort",
    ).reset_index(drop=True)
    if "rank" in frame:
        frame = frame.drop(columns=["rank"])
    frame.insert(0, "rank", range(1, len(frame) + 1))
    return frame


def get_top_10_recommendations(ranked_results: Any, top_k: int = 10) -> pd.DataFrame:
    """Return at most top_k already-ranked recommendations."""
    ranked = rank_patch_candidates(ranked_results)
    return ranked.head(max(0, int(top_k))).reset_index(drop=True)
