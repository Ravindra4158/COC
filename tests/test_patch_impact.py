import copy

import networkx as nx

from src.optimization.patch_impact import calculate_network_risk, evaluate_patch_impact, virtually_patch
from src.simulation.monte_carlo import run_baseline_simulation


def chain(two_vulnerabilities=False):
    graph = nx.DiGraph([("entry", "host"), ("host", "asset")])
    graph.nodes["host"]["vulnerabilities"] = ["v1", "v2"] if two_vulnerabilities else ["v1"]
    vulnerabilities = [{"vuln_id": "v1", "host_id": "host", "cvss": 7.0, "exploit_probability": 1.0}]
    if two_vulnerabilities:
        vulnerabilities.append({"vuln_id": "v2", "host_id": "host", "cvss": 6.0, "exploit_probability": 1.0})
    return graph, vulnerabilities


def test_risk_formula_and_virtual_patch_are_non_destructive():
    graph, vulnerabilities = chain()
    original_graph = copy.deepcopy(graph)
    original_vulnerabilities = copy.deepcopy(vulnerabilities)
    baseline = run_baseline_simulation(graph, vulnerabilities, ["entry"], ["asset"], n_simulations=20, seed=4)
    assert calculate_network_risk(baseline, {"asset": 1.0}) == 1.0
    assert virtually_patch("v1") == frozenset({"v1"})
    patched = evaluate_patch_impact({"host_id": "host", "vulnerability_id": "v1", "priority_score": 80, "cvss": 7, "exploit_probability": 1}, baseline, graph, vulnerabilities, ["entry"], {"asset": 1.0}, patch_simulations=20)
    assert patched["risk_before"] == 1.0
    assert patched["risk_after"] == 0.0
    assert patched["patch_value"] == 1.0
    assert graph.nodes["host"]["vulnerabilities"] == original_graph.nodes["host"]["vulnerabilities"]
    assert vulnerabilities == original_vulnerabilities


def test_second_vulnerability_preserves_access():
    graph, vulnerabilities = chain(two_vulnerabilities=True)
    baseline = run_baseline_simulation(graph, vulnerabilities, ["entry"], ["asset"], n_simulations=20, seed=4)
    patched = evaluate_patch_impact({"host_id": "host", "vulnerability_id": "v1"}, baseline, graph, vulnerabilities, ["entry"], {"asset": 1.0}, patch_simulations=20)
    assert patched["risk_after"] == 1.0
    assert patched["patch_value"] == 0.0


def test_unreachable_patch_has_no_risk_impact():
    graph, vulnerabilities = chain()
    graph.add_node("isolated", vulnerabilities=["v2"])
    vulnerabilities.append({"vuln_id": "v2", "host_id": "isolated", "cvss": 9.0, "exploit_probability": 1.0})
    baseline = run_baseline_simulation(graph, vulnerabilities, ["entry"], ["asset"], n_simulations=20, seed=4)
    patched = evaluate_patch_impact({"host_id": "isolated", "vulnerability_id": "v2"}, baseline, graph, vulnerabilities, ["entry"], {"asset": 1.0}, patch_simulations=20)
    assert patched["patch_value"] == 0.0
