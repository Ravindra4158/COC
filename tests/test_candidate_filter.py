import pandas as pd

from src.optimization.candidate_filter import filter_patch_candidates


def test_filter_keeps_reachable_attack_path_candidates():
    rows = pd.DataFrame([
        {"host_id": "reachable", "vulnerability_id": "v1", "attacker_reachability": 0.5, "reachable_critical_asset_count": 1},
        {"host_id": "isolated", "vulnerability_id": "v2", "attacker_reachability": 0.0, "reachable_critical_asset_count": 0},
    ])
    analysis = {
        "reachable_nodes": ["reachable"],
        "host_features": [{"host_id": "reachable", "reachable_critical_asset_count": 1}],
        "choke_points": [],
    }
    candidates = filter_patch_candidates(rows, analysis)
    assert [row["vulnerability_id"] for row in candidates] == ["v1"]


def test_filter_is_conservative_without_analysis():
    rows = [{"host_id": "unknown", "vulnerability_id": "v1"}]
    assert filter_patch_candidates(rows) == rows
