from collections.abc import Iterable, Mapping
from typing import Any

import networkx as nx


def normalize_distance(distance: int | float | None) -> float:
    """Convert a non-negative graph distance to [0, 1]."""
    if distance is None:
        return 0.0
    distance = float(distance)
    if distance < 0:
        raise ValueError("distance cannot be negative")
    return 1.0 / (1.0 + distance)


def get_distance_from_entries(graph: nx.DiGraph, host_id: Any, entry_points: Iterable[Any]) -> int | None:
    """Return the minimum directed distance from any valid entry point."""
    distances = []
    for entry_point in entry_points:
        if entry_point in graph and host_id in graph:
            try:
                distances.append(nx.shortest_path_length(graph, entry_point, host_id))
            except nx.NetworkXNoPath:
                continue
    return min(distances) if distances else None


def calculate_attacker_reachability(
    graph: nx.DiGraph,
    host_id: Any,
    entry_points: Iterable[Any],
    host_features: Iterable[Mapping[str, Any]] | None = None,
) -> tuple[float, int | None]:
    """Return normalized attacker reachability and its supporting distance."""
    distance = None
    if host_features is not None:
        feature = next((item for item in host_features if item.get("host_id") == host_id), None)
        if feature is not None:
            distance = feature.get("distance_from_entry")
    if distance is None:
        distance = get_distance_from_entries(graph, host_id, entry_points)
    return normalize_distance(distance), distance
