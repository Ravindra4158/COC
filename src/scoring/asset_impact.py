from collections.abc import Iterable, Mapping
from typing import Any

import networkx as nx


def _criticality_map(graph: nx.DiGraph, critical_assets: Iterable[Any] | Mapping[Any, float]) -> dict[Any, float]:
    if isinstance(critical_assets, Mapping):
        return {asset: float(value) for asset, value in critical_assets.items()}
    result = {}
    for asset in critical_assets:
        value = graph.nodes[asset].get("criticality", 1.0) if asset in graph else 1.0
        result[asset] = float(value)
    return result


def normalize_asset_criticality(value: float) -> float:
    value = float(value)
    if value < 0:
        raise ValueError("asset criticality cannot be negative")
    return min(1.0, value)


def calculate_asset_impact(
    graph: nx.DiGraph,
    host_id: Any,
    critical_assets: Iterable[Any] | Mapping[Any, float],
    downstream_assets: Iterable[Any] | None = None,
    nearest_critical_distance: int | float | None = None,
    simulation_result: Any | None = None,
) -> tuple[float, float]:
    """Return critical-asset exposure and the strongest downstream criticality."""
    criticalities = _criticality_map(graph, critical_assets)
    downstream = list(downstream_assets) if downstream_assets is not None else [
        asset for asset in criticalities if asset == host_id or nx.has_path(graph, host_id, asset)
    ]
    if not downstream or not criticalities:
        return 0.0, 0.0
    total_criticality = sum(normalize_asset_criticality(value) for value in criticalities.values()) or 1.0
    if simulation_result:
        probabilities = (
            simulation_result.get("critical_asset_probabilities", {})
            if isinstance(simulation_result, Mapping)
            else getattr(simulation_result, "critical_asset_probabilities", {})
        )
    else:
        probabilities = {}
    weighted_exposure = sum(
        normalize_asset_criticality(criticalities[asset]) * float(probabilities.get(asset, 1.0))
        for asset in downstream
    ) / total_criticality
    distance_factor = 1.0 / (1.0 + float(nearest_critical_distance)) if nearest_critical_distance is not None else 1.0
    exposure = min(1.0, 0.75 * weighted_exposure + 0.25 * distance_factor)
    strongest_criticality = max(normalize_asset_criticality(criticalities[asset]) for asset in downstream)
    return exposure, strongest_criticality
