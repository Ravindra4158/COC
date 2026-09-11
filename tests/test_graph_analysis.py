import networkx as nx

from src.graph.analysis import (
    analyze_attack_graph,
    calculate_downstream_critical_assets,
    calculate_host_features,
    find_choke_points,
)
from tests.test_paths import sample_graph


def test_choke_points_and_downstream_assets():
    graph = sample_graph()
    paths = [{"entry_point": 0, "target": 35, "path": [0, 12, 27, 35]}, {"entry_point": 0, "target": 39, "path": [0, 12, 27, 39]}]
    choke_points = find_choke_points(graph, paths)
    assert choke_points[0]["host_id"] in {0, 12, 27}
    assert next(item for item in choke_points if item["host_id"] == 27)["path_count"] == 2
    assert calculate_downstream_critical_assets(graph, [35, 39])[27] == [35, 39]


def test_host_features_and_high_level_analysis():
    graph = sample_graph()
    features = {item["host_id"]: item for item in calculate_host_features(graph, [0], [35, 39])}
    assert features[27]["distance_from_entry"] == 2
    assert features[27]["distance_to_nearest_critical_asset"] == 1
    assert features[27]["reachable_critical_asset_count"] == 2

    result = analyze_attack_graph(graph, [0, 1], [35, 39, 50])
    assert result["reachable_critical_assets"] == [35, 39]
    assert len(result["attack_paths"]) == 6
    assert result["shortest_paths"]
    assert result["host_features"]
