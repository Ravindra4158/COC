import networkx as nx

from src.graph.paths import (
    find_attack_paths,
    get_reachable_critical_assets,
    get_reachable_nodes,
    get_reachable_nodes_from_entries,
    get_shortest_attack_path,
    get_vulnerabilities_on_attack_paths,
)


def sample_graph():
    graph = nx.DiGraph([
        (0, 12), (12, 27), (27, 35), (27, 39), (0, 15), (15, 27), (1, 8), (8, 27),
    ])
    graph.add_nodes_from([50])
    graph.nodes[12]["vulnerabilities"] = ["V42"]
    graph.nodes[27]["vulnerabilities"] = ["V17", "V63"]
    return graph


def test_reachability_and_multiple_entries():
    graph = sample_graph()
    assert get_reachable_nodes(graph, 0) == {0, 12, 15, 27, 35, 39}
    assert get_reachable_nodes(graph, 50) == {50}
    assert get_reachable_nodes_from_entries(graph, [0, 1]) == {0, 1, 8, 12, 15, 27, 35, 39}


def test_critical_assets_and_shortest_path():
    graph = sample_graph()
    assert get_reachable_critical_assets(graph, [0], [35, 39, 50]) == {35: True, 39: True, 50: False}
    assert get_shortest_attack_path(graph, 0, 39) == {"entry_point": 0, "target": 39, "path": [0, 12, 27, 39], "length": 3}
    assert get_shortest_attack_path(graph, 0, 50) is None


def test_multiple_paths_and_vulnerabilities():
    graph = sample_graph()
    paths = find_attack_paths(graph, [0], [39], max_path_length=10)
    assert {tuple(item["path"]) for item in paths} == {(0, 12, 27, 39), (0, 15, 27, 39)}
    enriched = get_vulnerabilities_on_attack_paths(graph, paths)
    assert {item["vulnerability_id"] for item in enriched[0]["vulnerabilities"]} == {"V42", "V17", "V63"}
