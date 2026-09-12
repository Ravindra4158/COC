import networkx as nx
import pandas as pd


def _as_bool(value) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return bool(value)


def _node_sort_key(node: object) -> tuple[int, object]:
    try:
        return (0, int(node))  # type: ignore[arg-type]
    except (ValueError, TypeError):
        return (1, str(node))


def connect_disconnected_components(graph: nx.Graph | nx.DiGraph) -> nx.Graph | nx.DiGraph:
    """Connect adjacent components by their lowest-numbered nodes per development rule."""
    if len(graph) <= 1:
        return graph
    is_dir = graph.is_directed()
    comp_gen = nx.weakly_connected_components(graph) if is_dir else nx.connected_components(graph)
    comps = sorted(
        (sorted(c, key=_node_sort_key) for c in comp_gen),
        key=lambda c: _node_sort_key(c[0]),
    )
    for left, right in zip(comps, comps[1:]):
        graph.add_edge(left[0], right[0])
    return graph


def build_network_graph(
    hosts: pd.DataFrame,
    network_edges: pd.DataFrame,
    vulnerabilities=None,
    critical_assets=None,
    directed: bool = True,
    ensure_connected: bool = True,
) -> nx.Graph:
    """Build a directed or undirected network while preserving host annotations."""
    graph = nx.DiGraph() if directed else nx.Graph()
    for row in hosts.itertuples(index=False):
        graph.add_node(row.host_id, host_id=row.host_id, vulnerabilities=[], is_critical=False, is_entry_point=False)
        for column in ("criticality", "name", "is_entry_point"):
            if hasattr(row, column):
                value = getattr(row, column)
                graph.nodes[row.host_id][column] = _as_bool(value) if column == "is_entry_point" else value

    for row in network_edges.itertuples(index=False):
        src, dst = row.source, row.target
        if src not in graph:
            graph.add_node(src, host_id=src, vulnerabilities=[], is_critical=False, is_entry_point=False)
        if dst not in graph:
            graph.add_node(dst, host_id=dst, vulnerabilities=[], is_critical=False, is_entry_point=False)
        graph.add_edge(src, dst)

    if vulnerabilities is not None:
        for row in vulnerabilities.itertuples(index=False):
            if row.host_id not in graph:
                graph.add_node(row.host_id, host_id=row.host_id, vulnerabilities=[], is_critical=False, is_entry_point=False)
            if "vulnerabilities" not in graph.nodes[row.host_id]:
                graph.nodes[row.host_id]["vulnerabilities"] = []
            graph.nodes[row.host_id]["vulnerabilities"].append(row.vuln_id)

    if critical_assets is not None:
        for row in critical_assets.itertuples(index=False):
            if row.host_id not in graph:
                graph.add_node(row.host_id, host_id=row.host_id, vulnerabilities=[], is_critical=True, is_entry_point=False)
            attributes = graph.nodes[row.host_id]
            attributes["is_critical"] = True
            if hasattr(row, "criticality"):
                attributes["criticality"] = row.criticality

    # Guarantee all nodes have required attributes
    for n in graph.nodes:
        if "vulnerabilities" not in graph.nodes[n]:
            graph.nodes[n]["vulnerabilities"] = []
        if "is_critical" not in graph.nodes[n]:
            graph.nodes[n]["is_critical"] = False
        if "is_entry_point" not in graph.nodes[n]:
            graph.nodes[n]["is_entry_point"] = False

    if ensure_connected and len(graph) > 1:
        connect_disconnected_components(graph)
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
