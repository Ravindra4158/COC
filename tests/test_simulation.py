import networkx as nx

from src.simulation.monte_carlo import run_baseline_simulation, run_two_stage_simulation


def linear_graph(probability=1.0):
    graph = nx.DiGraph([(0, "a"), ("a", "b"), ("b", "asset")])
    graph.nodes["a"]["vulnerabilities"] = ["v-a"]
    graph.nodes["b"]["vulnerabilities"] = ["v-b"]
    return graph, [
        {"vuln_id": "v-a", "host_id": "a", "exploit_probability": probability},
        {"vuln_id": "v-b", "host_id": "b", "exploit_probability": probability},
    ]


def test_probability_one_and_zero():
    graph, vulnerabilities = linear_graph(1.0)
    result = run_baseline_simulation(graph, vulnerabilities, [0], ["asset"], n_simulations=20, seed=42)
    assert result.critical_asset_probabilities["asset"] == 1.0
    assert result.critical_asset_reach_probability == 1.0

    graph, vulnerabilities = linear_graph(0.0)
    result = run_baseline_simulation(graph, vulnerabilities, [0], ["asset"], n_simulations=20, seed=42)
    assert result.critical_asset_probabilities["asset"] == 0.0


def test_intermediate_probability_is_statistically_reasonable():
    graph = nx.DiGraph([(0, "a"), ("a", "asset")])
    graph.nodes["a"]["vulnerabilities"] = ["v-a"]
    vulnerabilities = [{"vuln_id": "v-a", "host_id": "a", "exploit_probability": 0.5}]
    result = run_baseline_simulation(graph, vulnerabilities, [0], ["asset"], n_simulations=2000, seed=42)
    assert 0.45 <= result.critical_asset_probabilities["asset"] <= 0.55
    assert result.vulnerability_statistics["v-a"]["configured_probability"] == 0.5


def test_reproducibility_and_different_seeds():
    graph, vulnerabilities = linear_graph(0.5)
    first = run_baseline_simulation(graph, vulnerabilities, [0], ["asset"], n_simulations=100, seed=42)
    second = run_baseline_simulation(graph, vulnerabilities, [0], ["asset"], n_simulations=100, seed=42)
    third = run_baseline_simulation(graph, vulnerabilities, [0], ["asset"], n_simulations=100, seed=43)
    assert first == second
    assert first != third


def test_disconnected_and_multiple_assets_and_entries():
    graph = nx.DiGraph([(0, "a"), (1, "b"), ("a", "asset-1"), ("b", "asset-2")])
    graph.nodes["a"]["vulnerabilities"] = ["v-a"]
    graph.nodes["b"]["vulnerabilities"] = ["v-b"]
    vulnerabilities = [
        {"vuln_id": "v-a", "host_id": "a", "exploit_probability": 1.0},
        {"vuln_id": "v-b", "host_id": "b", "exploit_probability": 1.0},
    ]
    result = run_baseline_simulation(graph, vulnerabilities, [0, 1], ["asset-1", "asset-2", "isolated"], n_simulations=100, seed=42)
    assert result.critical_asset_probabilities["asset-1"] > 0
    assert result.critical_asset_probabilities["asset-2"] > 0
    assert result.critical_asset_probabilities["isolated"] == 0
    assert result.critical_asset_reach_probability == 1.0


def test_two_stage_result_respects_requested_count():
    graph, vulnerabilities = linear_graph(1.0)
    result = run_two_stage_simulation(graph, vulnerabilities, [0], ["asset"], n_simulations=100, seed=42, screening_simulations=20)
    assert result.simulations == 100
    assert result.critical_asset_reach_probability == 1.0
