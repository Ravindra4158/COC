from src.data.loader import load_all_data
from src.data.validator import validate_all
from src.graph.builder import (
    build_network_graph,
    get_critical_assets,
    get_entry_points,
    get_vulnerable_hosts,
)


def test_graph_contains_nodes_edges_and_associations():
    data = load_all_data("data/raw")
    validate_all(data)
    graph = build_network_graph(**{
        "hosts": data["hosts"],
        "network_edges": data["network_edges"],
        "vulnerabilities": data["vulnerabilities"],
        "critical_assets": data["critical_assets"],
    })
    assert set(graph.nodes) == {"h1", "h2", "h3", "h4"}
    assert graph.has_edge("h1", "h2")
    assert graph.nodes["h1"]["vulnerabilities"] == ["v1"]
    assert set(get_critical_assets(graph)) == {"h3", "h4"}
    assert set(get_vulnerable_hosts(graph)) == {"h1", "h2", "h3", "h4"}
    assert get_entry_points(graph) == []


def test_multiple_vulnerabilities_are_attached():
    data = load_all_data("data/raw")
    extra = data["vulnerabilities"].iloc[[0]].copy()
    extra["vuln_id"] = "v-extra"
    data["vulnerabilities"] = __import__("pandas").concat([data["vulnerabilities"], extra], ignore_index=True)
    graph = build_network_graph(data["hosts"], data["network_edges"], data["vulnerabilities"], data["critical_assets"])
    assert graph.nodes["h1"]["vulnerabilities"] == ["v1", "v-extra"]
