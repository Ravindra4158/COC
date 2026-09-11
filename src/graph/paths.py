from collections.abc import Iterable
from typing import Any

import networkx as nx


def is_reachable(graph: nx.DiGraph, source: Any, target: Any) -> bool:
    """Return whether target can be reached from source, including source == target."""
    if source not in graph or target not in graph:
        return False
    return nx.has_path(graph, source, target)


def get_reachable_nodes(graph: nx.DiGraph, source: Any) -> set[Any]:
    """Return source and every node reachable from it."""
    if source not in graph:
        return set()
    return {source} | nx.descendants(graph, source)


def get_reachable_nodes_from_entries(graph: nx.DiGraph, entry_points: Iterable[Any]) -> set[Any]:
    """Return the union of nodes reachable from all entry points."""
    reachable = set()
    for entry_point in entry_points:
        reachable.update(get_reachable_nodes(graph, entry_point))
    return reachable


def get_paths_to_target(
    graph: nx.DiGraph,
    source: Any,
    target: Any,
    max_path_length: int | None = 10,
    max_paths: int | None = 100,
) -> list[list[Any]]:
    """Return bounded simple paths from source to target."""
    if source not in graph or target not in graph:
        return []
    paths = nx.all_simple_paths(graph, source, target, cutoff=max_path_length)
    result = []
    for path in paths:
        result.append(path)
        if max_paths is not None and len(result) >= max_paths:
            break
    return result


def get_shortest_path(graph: nx.DiGraph, source: Any, target: Any) -> list[Any] | None:
    """Return the shortest directed path, or None when no path exists."""
    if source not in graph or target not in graph:
        return None
    try:
        return nx.shortest_path(graph, source, target)
    except nx.NetworkXNoPath:
        return None


def get_reachable_critical_assets(
    graph: nx.DiGraph,
    entry_points: Iterable[Any],
    critical_assets: Iterable[Any],
) -> dict[Any, bool]:
    """Map each supplied critical asset to its deterministic reachability."""
    reachable = get_reachable_nodes_from_entries(graph, entry_points)
    return {asset: asset in reachable for asset in critical_assets}


def find_attack_paths(
    graph: nx.DiGraph,
    entry_points: Iterable[Any],
    critical_assets: Iterable[Any],
    max_path_length: int | None = 10,
    max_paths_per_target: int | None = 100,
) -> list[dict[str, Any]]:
    """Find bounded attacker-to-critical-asset paths."""
    paths = []
    for entry_point in entry_points:
        for target in critical_assets:
            if max_paths_per_target == 1:
                shortest = get_shortest_path(graph, entry_point, target)
                if shortest is not None:
                    paths.append({"entry_point": entry_point, "target": target, "path": shortest})
                continue
            for path in get_paths_to_target(graph, entry_point, target, max_path_length, max_paths_per_target):
                paths.append({"entry_point": entry_point, "target": target, "path": path})
    return paths


def get_shortest_attack_path(graph: nx.DiGraph, entry_point: Any, critical_asset: Any) -> dict[str, Any] | None:
    """Return a structured shortest attack path, or None when unreachable."""
    path = get_shortest_path(graph, entry_point, critical_asset)
    if path is None:
        return None
    return {"entry_point": entry_point, "target": critical_asset, "path": path, "length": len(path) - 1}


def get_paths_to_critical_assets(
    graph: nx.DiGraph,
    entry_point: Any,
    critical_assets: Iterable[Any],
    max_path_length: int | None = 10,
    max_paths_per_target: int | None = 100,
) -> list[dict[str, Any]]:
    """Convenience wrapper for paths from one entry point."""
    return find_attack_paths(graph, [entry_point], critical_assets, max_path_length, max_paths_per_target)


def get_vulnerabilities_on_path(graph: nx.DiGraph, path: Iterable[Any]) -> list[dict[str, Any]]:
    """Return vulnerability IDs attached to hosts on a path."""
    vulnerabilities = []
    for host_id in path:
        for vulnerability_id in graph.nodes[host_id].get("vulnerabilities", []):
            vulnerabilities.append({"host_id": host_id, "vulnerability_id": vulnerability_id})
    return vulnerabilities


def get_vulnerabilities_on_attack_paths(graph: nx.DiGraph, attack_paths: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Copy attack-path records and add their path vulnerability associations."""
    return [
        {**attack_path, "vulnerabilities": get_vulnerabilities_on_path(graph, attack_path["path"])}
        for attack_path in attack_paths
    ]
