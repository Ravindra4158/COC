import networkx as nx
import pandas as pd

from src.scoring.priority_score import calculate_priority_score, normalize_cvss, score_all_vulnerabilities
from src.simulation.monte_carlo import MonteCarloResult


def test_cvss_normalization_and_score_boundaries():
    assert normalize_cvss(0) == 0.0
    assert normalize_cvss(5) == 0.5
    assert normalize_cvss(10) == 1.0
    assert calculate_priority_score(0, 0, 0, 0, 0) == 0.0
    assert calculate_priority_score(1, 1, 1, 1, 1) == 100.0


def scoring_fixture():
    graph = nx.DiGraph([("entry", "choke"), ("choke", "asset")])
    graph.add_node("isolated")
    graph.nodes["choke"]["vulnerabilities"] = ["v-b"]
    graph.nodes["isolated"]["vulnerabilities"] = ["v-a"]
    vulnerabilities = pd.DataFrame([
        {"vuln_id": "v-a", "host_id": "isolated", "cvss": 9.5, "exploit_probability": 0.9},
        {"vuln_id": "v-b", "host_id": "choke", "cvss": 7.5, "exploit_probability": 0.8},
    ])
    return graph, vulnerabilities


def test_graph_context_can_beat_higher_cvss():
    graph, vulnerabilities = scoring_fixture()
    result = score_all_vulnerabilities(graph, vulnerabilities, ["entry", "choke", "isolated", "asset"], ["entry"], {"asset": 1.0}, output_path=None)
    scores = result.set_index("vulnerability_id")["priority_score"]
    assert scores["v-b"] > scores["v-a"]
    assert result.loc[result["vulnerability_id"] == "v-a", "attacker_reachability"].iloc[0] == 0.0


def test_critical_asset_disconnect_reduces_score():
    graph, vulnerabilities = scoring_fixture()
    connected = score_all_vulnerabilities(graph, vulnerabilities.iloc[[1]], ["entry", "choke", "isolated", "asset"], ["entry"], {"asset": 1.0}, output_path=None).iloc[0]
    graph.remove_edge("choke", "asset")
    disconnected = score_all_vulnerabilities(graph, vulnerabilities.iloc[[1]], ["entry", "choke", "isolated", "asset"], ["entry"], {"asset": 1.0}, output_path=None).iloc[0]
    assert connected["critical_asset_exposure"] > disconnected["critical_asset_exposure"]
    assert connected["priority_score"] > disconnected["priority_score"]


def test_monte_carlo_features_are_consumed_and_rank_is_deterministic(tmp_path):
    graph, vulnerabilities = scoring_fixture()
    simulation = MonteCarloResult(100, 42, 0.75, {"asset": 0.75}, {"choke": {"compromise_probability": 0.72}}, {})
    result = score_all_vulnerabilities(graph, vulnerabilities, ["entry", "choke", "isolated", "asset"], ["entry"], {"asset": 1.0}, simulation, output_path=tmp_path / "ranked.csv")
    assert result.iloc[0]["vulnerability_id"] == "v-b"
    assert result.iloc[0]["monte_carlo_host_compromise_probability"] == 0.72
    assert list(result["rank"]) == [1, 2]
    assert (tmp_path / "ranked.csv").is_file()
