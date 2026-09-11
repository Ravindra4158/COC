from collections.abc import Iterable, Mapping
from typing import Any


def _rows(values: Any) -> list[dict[str, Any]]:
    if hasattr(values, "to_dict"):
        return values.to_dict("records")
    return [dict(value) for value in values]


def filter_patch_candidates(
    ranked_vulnerabilities: Any,
    graph_analysis: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Conservatively retain vulnerabilities that can affect an attack path.

    When graph analysis is unavailable, every row is retained because filtering
    without reachability evidence could discard a useful patch candidate.
    """
    rows = _rows(ranked_vulnerabilities)
    if graph_analysis is None:
        return rows
    reachable_nodes = set(graph_analysis.get("reachable_nodes", []))
    feature_map = {item["host_id"]: item for item in graph_analysis.get("host_features", [])}
    choke_hosts = {item["host_id"] for item in graph_analysis.get("choke_points", [])}
    candidates = []
    for row in rows:
        host_id = row.get("host_id")
        feature = feature_map.get(host_id, {})
        reachable = row.get("attacker_reachability", feature.get("distance_from_entry") is not None)
        downstream = row.get("reachable_critical_asset_count", feature.get("reachable_critical_asset_count", 0))
        path_frequency = row.get("path_frequency", 0)
        if host_id in reachable_nodes and (reachable or downstream > 0 or path_frequency > 0 or host_id in choke_hosts):
            candidates.append(row)
    return candidates
