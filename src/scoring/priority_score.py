from collections import defaultdict
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import networkx as nx
import numpy as np
import pandas as pd

from src.graph.analysis import analyze_attack_graph
from .asset_impact import calculate_asset_impact
from .exploit_probability import get_exploit_probability
from .reachability import calculate_attacker_reachability

DEFAULT_WEIGHTS = {
    "severity": 0.20,
    "exploit_probability": 0.20,
    "attacker_reachability": 0.20,
    "critical_asset_exposure": 0.25,
    "graph_importance": 0.15,
}


def normalize_cvss(value: float) -> float:
    value = float(value)
    if not 0.0 <= value <= 10.0:
        raise ValueError("CVSS must be between 0 and 10")
    return value / 10.0


def normalize_count(value: int | float, maximum: int | float) -> float:
    if maximum <= 0:
        return 0.0
    return min(1.0, max(0.0, float(value) / float(maximum)))


def _rows(values: Any) -> list[dict[str, Any]]:
    if hasattr(values, "to_dict"):
        return values.to_dict("records")
    if isinstance(values, Mapping):
        return [dict(value, vuln_id=key) if isinstance(value, Mapping) else {"vuln_id": key, "exploit_probability": value} for key, value in values.items()]
    return [dict(value) for value in values]


def _simulation_field(simulation_result: Any | None, field: str, default: Any) -> Any:
    if simulation_result is None:
        return default
    if isinstance(simulation_result, Mapping):
        return simulation_result.get(field, default)
    return getattr(simulation_result, field, default)


def _criticality_map(graph: nx.DiGraph | nx.Graph, critical_assets: Any) -> dict[Any, float]:
    if hasattr(critical_assets, "to_dict"):
        result = {}
        for row in critical_assets.to_dict("records"):
            asset = row["host_id"]
            result[asset] = float(row.get("criticality", row.get("impact_weight", graph.nodes[asset].get("criticality", 1.0))))
        return result
    if isinstance(critical_assets, Mapping):
        return {key: float(value) for key, value in critical_assets.items()}
    return {asset: float(graph.nodes[asset].get("criticality", 1.0)) for asset in critical_assets}


def _weight_map(weights: Mapping[str, float] | None) -> dict[str, float]:
    values = dict(DEFAULT_WEIGHTS if weights is None else weights)
    missing = set(DEFAULT_WEIGHTS) - set(values)
    if missing:
        raise ValueError(f"missing scoring weights: {sorted(missing)}")
    if any(float(value) < 0 for value in values.values()):
        raise ValueError("scoring weights cannot be negative")
    total = sum(float(values[key]) for key in DEFAULT_WEIGHTS)
    if total <= 0:
        raise ValueError("scoring weights must have a positive sum")
    return {key: float(values[key]) / total for key in DEFAULT_WEIGHTS}


def calculate_priority_score(
    normalized_cvss: float,
    exploit_probability: float,
    attacker_reachability: float,
    critical_asset_exposure: float,
    graph_importance: float,
    weights: Mapping[str, float] | None = None,
) -> float:
    """Calculate the explainable weighted Phase 4 score on a 0-100 scale."""
    components = {
        "severity": normalized_cvss,
        "exploit_probability": exploit_probability,
        "attacker_reachability": attacker_reachability,
        "critical_asset_exposure": critical_asset_exposure,
        "graph_importance": graph_importance,
    }
    if any(not 0.0 <= float(value) <= 1.0 for value in components.values()):
        raise ValueError("priority score components must be between 0 and 1")
    normalized_weights = _weight_map(weights)
    return round(100.0 * sum(normalized_weights[name] * value for name, value in components.items()), 6)


def score_all_vulnerabilities(
    graph: nx.DiGraph | nx.Graph,
    vulnerabilities: Any,
    hosts: Any,
    entry_points: Iterable[Any],
    critical_assets: Any,
    simulation_result: Any | None = None,
    graph_analysis: Mapping[str, Any] | None = None,
    weights: Mapping[str, float] | None = None,
    output_path: str | Path | None = "output/ranked_vulnerabilities.csv",
) -> pd.DataFrame:
    """Score and rank every host-vulnerability pair with attack-path awareness."""
    vulnerability_rows = _rows(vulnerabilities)
    host_ids = set(hosts["host_id"]) if hasattr(hosts, "columns") else set(hosts)
    if set(graph.nodes) != host_ids:
        host_ids = set(graph.nodes)
    criticality_map = _criticality_map(graph, critical_assets)
    critical_asset_ids = list(criticality_map)
    analysis = graph_analysis or analyze_attack_graph(graph, entry_points, critical_asset_ids)
    features = {item["host_id"]: item for item in analysis["host_features"]}
    choke_points = {item["host_id"]: item for item in analysis["choke_points"]}
    max_path_frequency = max((item["path_count"] for item in choke_points.values()), default=0)
    max_asset_count = max((item["reachable_critical_asset_count"] for item in features.values()), default=0)
    host_statistics = _simulation_field(simulation_result, "host_statistics", {})
    asset_probabilities = _simulation_field(simulation_result, "critical_asset_probabilities", {})

    host_vulns_map = defaultdict(list)
    for v in vulnerability_rows:
        host_vulns_map[v["host_id"]].append(v)

    results = []
    for vulnerability in vulnerability_rows:
        host_id = vulnerability["host_id"]
        if host_id not in host_ids or host_id not in graph:
            raise ValueError(f"vulnerability {vulnerability.get('vuln_id')} references unknown host {host_id}")
        vulnerability_id = vulnerability.get("vulnerability_id", vulnerability.get("vuln_id"))
        if vulnerability_id is None:
            raise ValueError("each vulnerability requires vuln_id or vulnerability_id")
        row_features = features.get(host_id, {"distance_from_entry": None, "distance_to_nearest_critical_asset": None, "reachable_critical_assets": [], "reachable_critical_asset_count": 0})
        exploit_probability = get_exploit_probability(vulnerability)

        # Compute marginal enablement ΔP_comp (probability this vuln alone opens host)
        siblings = [
            o for o in host_vulns_map[host_id]
            if o.get("vulnerability_id", o.get("vuln_id")) != vulnerability_id
        ]
        sibling_fail = float(np.prod([1.0 - get_exploit_probability(s) for s in siblings])) if siblings else 1.0
        individual_enablement = exploit_probability * sibling_fail

        attacker_reachability, distance_from_entry = calculate_attacker_reachability(graph, host_id, entry_points, analysis["host_features"])
        downstream = row_features["reachable_critical_assets"]
        asset_exposure, asset_criticality = calculate_asset_impact(graph, host_id, criticality_map, downstream, row_features["distance_to_nearest_critical_asset"], simulation_result)
        path_frequency = choke_points.get(host_id, {}).get("path_count", 0)
        graph_importance = 0.5 * normalize_count(path_frequency, max_path_frequency) + 0.5 * normalize_count(row_features["reachable_critical_asset_count"], max_asset_count)
        host_stat = host_statistics.get(host_id, {})
        monte_carlo_asset_probability = max((float(asset_probabilities.get(asset, 0.0)) for asset in downstream), default=0.0)

        results.append({
            "host_id": host_id,
            "vulnerability_id": vulnerability_id,
            "vuln_id": vulnerability.get("vuln_id", vulnerability_id),
            "cvss": float(vulnerability["cvss"]),
            "normalized_cvss": normalize_cvss(vulnerability["cvss"]),
            "exploit_probability": exploit_probability,
            "individual_enablement": round(individual_enablement, 6),
            "marginal_enablement": round(individual_enablement, 6),
            "attacker_reachability": attacker_reachability,
            "distance_from_entry": distance_from_entry,
            "critical_asset_exposure": asset_exposure,
            "asset_criticality": asset_criticality,
            "nearest_critical_distance": row_features["distance_to_nearest_critical_asset"],
            "reachable_critical_asset_count": row_features["reachable_critical_asset_count"],
            "path_frequency": path_frequency,
            "graph_importance": graph_importance,
            "monte_carlo_host_compromise_probability": float(host_stat.get("compromise_probability", 0.0)),
            "monte_carlo_critical_asset_probability": monte_carlo_asset_probability,
        })

    for result in results:
        result["priority_score"] = calculate_priority_score(
            result["normalized_cvss"], result["exploit_probability"], result["attacker_reachability"], result["critical_asset_exposure"], result["graph_importance"], weights
        )

    frame = pd.DataFrame(results)
    if frame.empty:
        frame["rank"] = pd.Series(dtype="int64")
        return frame
    frame = frame.sort_values(
        ["priority_score", "critical_asset_exposure", "attacker_reachability", "cvss", "host_id", "vulnerability_id"],
        ascending=[False, False, False, False, True, True],
        kind="mergesort",
    ).reset_index(drop=True)
    frame.insert(0, "rank", range(1, len(frame) + 1))
    if output_path is not None:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        frame.to_csv(output_path, index=False)
    return frame
