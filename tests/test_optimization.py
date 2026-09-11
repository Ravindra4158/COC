import pandas as pd

from src.optimization.ranking import get_top_10_recommendations, rank_patch_candidates


def test_rank_uses_patch_value_and_deterministic_ties():
    rows = pd.DataFrame([
        {"host_id": "b", "vulnerability_id": "v2", "patch_value": 0.2, "risk_reduction_percent": 20, "priority_score": 80, "cvss": 8},
        {"host_id": "a", "vulnerability_id": "v1", "patch_value": 0.7, "risk_reduction_percent": 70, "priority_score": 70, "cvss": 7},
        {"host_id": "c", "vulnerability_id": "v3", "patch_value": 0.7, "risk_reduction_percent": 70, "priority_score": 70, "cvss": 7},
    ])
    ranked = rank_patch_candidates(rows)
    assert list(ranked["vulnerability_id"]) == ["v1", "v3", "v2"]
    assert list(ranked["rank"]) == [1, 2, 3]


def test_top_ten_handles_large_and_small_inputs():
    rows = pd.DataFrame([{"host_id": str(i), "vulnerability_id": f"v{i}", "patch_value": i / 20} for i in range(15)])
    assert len(get_top_10_recommendations(rows)) == 10
    assert get_top_10_recommendations(rows).iloc[-1]["rank"] == 10
    assert len(get_top_10_recommendations(rows.head(5))) == 5
