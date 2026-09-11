import networkx as nx
import pandas as pd

from src.scoring.priority_score import score_all_vulnerabilities
from src.simulation.monte_carlo import run_baseline_simulation


def test_missing_entry_points_produce_zero_exposure():
    graph = nx.DiGraph([("host", "asset")])
    graph.nodes["host"]["vulnerabilities"] = ["v1"]
    vulnerabilities = [{"vuln_id": "v1", "host_id": "host", "exploit_probability": 1.0}]
    result = run_baseline_simulation(graph, vulnerabilities, [], ["asset"], n_simulations=20, seed=7)
    assert result.critical_asset_reach_probability == 0.0
    assert result.critical_asset_probabilities["asset"] == 0.0


def test_no_critical_assets_and_no_vulnerabilities_are_valid():
    graph = nx.DiGraph([("entry", "host")])
    empty = pd.DataFrame(columns=["vuln_id", "host_id", "cvss", "exploit_probability"])
    result = run_baseline_simulation(graph, empty, ["entry"], [], n_simulations=5, seed=7)
    assert result.critical_asset_reach_probability == 0.0
    scored = score_all_vulnerabilities(graph, empty, ["entry", "host"], ["entry"], {}, output_path=None)
    assert scored.empty


def test_simulation_is_reproducible_with_stage_metadata():
    graph = nx.DiGraph([("entry", "asset")])
    first = run_baseline_simulation(graph, [], ["entry"], ["asset"], n_simulations=20, seed=11)
    second = run_baseline_simulation(graph, [], ["entry"], ["asset"], n_simulations=20, seed=11)
    assert first == second
    assert first.to_dict()["total_simulations"] == 20