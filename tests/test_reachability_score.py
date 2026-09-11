import networkx as nx

from src.scoring.reachability import calculate_attacker_reachability, normalize_distance


def test_distance_normalization():
    assert normalize_distance(None) == 0.0
    assert normalize_distance(0) == 1.0
    assert normalize_distance(1) == 0.5


def test_reachable_and_unreachable_hosts():
    graph = nx.DiGraph([(0, "reachable")])
    assert calculate_attacker_reachability(graph, "reachable", [0]) == (0.5, 1)
    assert calculate_attacker_reachability(graph, "isolated", [0]) == (0.0, None)
