import networkx as nx
import pandas as pd


def _as_bool(value) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return bool(value)


def build_network_graph(hosts: pd.DataFrame, network_edges: pd.DataFrame, vulnerabilities=None, critical_assets=None, directed: bool = True) -> nx.Graph:
    """Build a directed or undirected network while preserving host annotations."""
    graph = nx.DiGraph() if directed else nx.Graph()
    for row in hosts.itertuples(index=False):
        graph.add_node(row.host_id, host_id=row.host_id, vulnerabilities=[], is_critical=False, is_entry_point=False)
        for column in ("criticality", "name", "is_entry_point"):
            if hasattr(row, column):
                value = getattr(row, column)
                graph.nodes[row.host_id][column] = _as_bool(value) if column == "is_entry_point" else value
    graph.add_edges_from((row.source, row.target) for row in network_edges.itertuples(index=False))
    if vulnerabilities is not None:
        for row in vulnerabilities.itertuples(index=False):
            graph.nodes[row.host_id]["vulnerabilities"].append(row.vuln_id)
    if critical_assets is not None:
        for row in critical_assets.itertuples(index=False):
            attributes = graph.nodes[row.host_id]
            attributes["is_critical"] = True
            if hasattr(row, "criticality"):
                attributes["criticality"] = row.criticality
    return graph


def get_critical_assets(graph: nx.DiGraph) -> list:
    return [node for node, attributes in graph.nodes(data=True) if attributes.get("is_critical")]


def get_entry_points(graph: nx.DiGraph) -> list:
    return [node for node, attributes in graph.nodes(data=True) if attributes.get("is_entry_point")]


def get_vulnerable_hosts(graph: nx.DiGraph) -> list:
    return [node for node, attributes in graph.nodes(data=True) if attributes.get("vulnerabilities")]


def build_network(edges: pd.DataFrame, hosts: pd.DataFrame) -> nx.DiGraph:
    """Backward-compatible wrapper for the original two-argument builder."""
    return build_network_graph(hosts, edges)
