import networkx as nx
import numpy as np

from src.simulation.attacker import simulate_attack


def test_attacker_tracks_success_and_failure():
    graph = nx.DiGraph([(0, 1), (1, 2)])
    graph.nodes[1]["vulnerabilities"] = ["v1"]
    graph.nodes[2]["vulnerabilities"] = []
    vulnerabilities = {"v1": {"host_id": 1, "exploit_probability": 1.0}}
    state = simulate_attack(graph, vulnerabilities, [0], {2}, np.random.Generator(np.random.PCG64(1)))
    assert state.compromised_hosts == {0, 1, 2}
    assert state.successful_exploits == {"v1"}
    assert state.reached_critical_assets == {2}


def test_failed_exploit_blocks_target():
    graph = nx.DiGraph([(0, 1), (1, 2)])
    graph.nodes[1]["vulnerabilities"] = ["v1"]
    vulnerabilities = {"v1": {"host_id": 1, "exploit_probability": 0.0}}
    state = simulate_attack(graph, vulnerabilities, [0], {2}, np.random.Generator(np.random.PCG64(1)))
    assert state.compromised_hosts == {0}
    assert state.failed_exploits == {"v1"}
    assert state.reached_critical_assets == set()
