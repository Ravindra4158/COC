from collections import defaultdict
from collections.abc import Iterable
from typing import Any

import networkx as nx

from .paths import (
    find_attack_paths,
    get_reachable_nodes_from_entries,
    get_reachable_critical_assets,
    get_shortest_attack_path,
    get_vulnerabilities_on_attack_paths,
)


def calculate_path_frequency(graph: nx.DiGraph, attack_paths: Iterable[dict[str, Any]]) -> dict[Any, dict[str, Any]]:
    """Count path occurrences and distinct targets for every host on attack paths."""
    frequencies = defaultdict(lambda: {"path_count": 0, "critical_assets_reached": set()})
    for attack_path in attack_paths:
        target = attack_path["target"]
        for host_id in attack_path["path"]:
            frequencies[host_id]["path_count"] += 1
            frequencies[host_id]["critical_assets_reached"].add(target)
    return {
        host_id: {
            "path_count": values["path_count"],
            "critical_assets_reached": sorted(values["critical_assets_reached"], key=str),
        }
        for host_id, values in frequencies.items()
        if host_id in graph
    }


def find_choke_points(graph: nx.DiGraph, attack_paths: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return path-participating hosts ordered by path frequency."""
    frequencies = calculate_path_frequency(graph, attack_paths)
    return [
        {"host_id": host_id, **values}
        for host_id, values in sorted(frequencies.items(), key=lambda item: (-item[1]["path_count"], str(item[0])))
    ]


def calculate_downstream_critical_assets(graph: nx.DiGraph, critical_assets: Iterable[Any]) -> dict[Any, list[Any]]:
    """Map every host to critical assets reachable downstream, including itself."""
    critical_assets = list(critical_assets)
    return {
        host_id: sorted(
            {asset for asset in critical_assets if asset == host_id or nx.has_path(graph, host_id, asset)},
            key=str,
        )
        for host_id in graph.nodes
    }


def calculate_host_features(
    graph: nx.DiGraph,
    entry_points: Iterable[Any],
    critical_assets: Iterable[Any],
) -> list[dict[str, Any]]:
    """Calculate deterministic distances and downstream critical-asset features."""
    entry_points = list(entry_points)
    critical_assets = list(critical_assets)
    distance_from_entry = {}
    for entry_point in entry_points:
        if entry_point in graph:
            for host_id, distance in nx.single_source_shortest_path_length(graph, entry_point).items():
                distance_from_entry[host_id] = min(distance_from_entry.get(host_id, distance), distance)
    reverse_graph = graph.reverse(copy=False) if graph.is_directed() else graph
    distance_to_critical = {}
    for asset in critical_assets:
        if asset in graph:
            for host_id, distance in nx.single_source_shortest_path_length(reverse_graph, asset).items():
                distance_to_critical[host_id] = min(distance_to_critical.get(host_id, distance), distance)
    downstream = calculate_downstream_critical_assets(graph, critical_assets)
    return [
        {
            "host_id": host_id,
            "distance_from_entry": distance_from_entry.get(host_id),
            "distance_to_nearest_critical_asset": distance_to_critical.get(host_id),
            "reachable_critical_assets": downstream[host_id],
            "reachable_critical_asset_count": len(downstream[host_id]),
        }
        for host_id in graph.nodes
    ]


def analyze_attack_graph(
    graph: nx.DiGraph,
    entry_points: Iterable[Any],
    critical_assets: Iterable[Any],
    max_path_length: int | None = 10,
    max_paths_per_target: int | None = 100,
) -> dict[str, Any]:
    """Return the complete deterministic Phase 2 attack-graph analysis."""
    entry_points = list(entry_points)
    critical_assets = list(critical_assets)
    attack_paths = find_attack_paths(graph, entry_points, critical_assets, max_path_length, max_paths_per_target)
    shortest_paths = [
        shortest_path
        for entry_point in entry_points
        for asset in critical_assets
        if (shortest_path := get_shortest_attack_path(graph, entry_point, asset)) is not None
    ]
    reachable_assets = get_reachable_critical_assets(graph, entry_points, critical_assets)
    return {
        "entry_points": entry_points,
        "reachable_nodes": sorted(get_reachable_nodes_from_entries(graph, entry_points), key=str),
        "reachable_critical_assets": [asset for asset, reachable in reachable_assets.items() if reachable],
        "attack_paths": get_vulnerabilities_on_attack_paths(graph, attack_paths),
        "shortest_paths": shortest_paths,
        "host_features": calculate_host_features(graph, entry_points, critical_assets),
        "choke_points": find_choke_points(graph, attack_paths),
    }
