from collections.abc import Iterable, Mapping
from hashlib import sha256
from pathlib import Path
from typing import Any

import pandas as pd

from src.simulation.budget import MAX_ATTACK_STEPS, get_simulation_budget
from src.simulation.monte_carlo import run_baseline_simulation
from .candidate_filter import filter_patch_candidates

DEFAULT_PATCH_SIMULATIONS = 500


def _field(value: Any, name: str, default: Any = None) -> Any:
    if value is None:
        return default
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _criticality_map(critical_assets: Any) -> dict[Any, float]:
    if hasattr(critical_assets, "to_dict"):
        return {
            row["host_id"]: float(row.get("criticality", row.get("impact_weight", 1.0)))
            for row in critical_assets.to_dict("records")
        }
    if isinstance(critical_assets, Mapping):
        return {asset: float(value) for asset, value in critical_assets.items()}
    return {asset: 1.0 for asset in critical_assets}


def calculate_network_risk(simulation_result: Any, critical_assets: Any) -> float:
    """Calculate weighted critical-asset exposure from one simulation result."""
    probabilities = _field(simulation_result, "critical_asset_probabilities", {}) or {}
    criticalities = _criticality_map(critical_assets)
    return max(0.0, sum(max(0.0, float(probabilities.get(asset, 0.0))) * max(0.0, criticality) for asset, criticality in criticalities.items()))


def virtually_patch(vulnerability_id: Any, disabled_vulnerabilities: Iterable[Any] | None = None) -> frozenset[Any]:
    """Return a temporary disabled-vulnerability set without mutating source data."""
    disabled = set(disabled_vulnerabilities or ())
    disabled.add(vulnerability_id)
    return frozenset(disabled)


def _stable_patch_seed(seed: int, vulnerability_id: Any) -> int:
    digest = sha256(str(vulnerability_id).encode("utf-8")).digest()
    return seed + int.from_bytes(digest[:4], "big")


def evaluate_patch_impact(
    candidate: Mapping[str, Any],
    baseline_result: Any,
    graph,
    vulnerabilities: Any,
    entry_points: Iterable[Any],
    critical_assets: Any,
    patch_simulations: int = DEFAULT_PATCH_SIMULATIONS,
    max_steps: int = MAX_ATTACK_STEPS,
) -> dict[str, Any]:
    """Evaluate one candidate by disabling only its vulnerability in a temporary simulation."""
    vulnerability_id = candidate.get("vulnerability_id", candidate.get("vuln_id"))
    if vulnerability_id is None:
        raise ValueError("patch candidate requires vulnerability_id or vuln_id")
    simulations = get_simulation_budget(patch_simulations)
    risk_before = calculate_network_risk(baseline_result, critical_assets)
    baseline_seed = int(_field(baseline_result, "seed", 42))
    patched_result = run_baseline_simulation(
        graph,
        vulnerabilities,
        entry_points,
        list(_criticality_map(critical_assets)),
        n_simulations=simulations,
        seed=_stable_patch_seed(baseline_seed, vulnerability_id),
        max_steps=max_steps,
        disabled_vulnerabilities=set(virtually_patch(vulnerability_id)),
    )
    risk_after = calculate_network_risk(patched_result, critical_assets)
    patch_value = max(0.0, risk_before - risk_after)
    reduction_percent = 100.0 * patch_value / risk_before if risk_before > 0 else 0.0
    result = dict(candidate)
    result.update({
        "vulnerability_id": vulnerability_id,
        "risk_before": risk_before,
        "risk_after": max(0.0, risk_after),
        "patch_value": patch_value,
        "risk_reduction_percent": max(0.0, reduction_percent),
        "critical_assets_affected": list(candidate.get("critical_assets_affected", [])),
        "attack_path_count": int(candidate.get("path_frequency", 0)),
        "patch_priority_score": patch_value,
    })
    if "patch_cost" in candidate and candidate["patch_cost"] not in (None, ""):
        cost = float(candidate["patch_cost"])
        if cost > 0:
            result["patch_efficiency"] = patch_value / cost
    return result


def evaluate_all_patch_impacts(
    ranked_vulnerabilities: Any,
    graph,
    vulnerabilities: Any,
    entry_points: Iterable[Any],
    critical_assets: Any,
    graph_analysis: Mapping[str, Any] | None = None,
    baseline_result: Any | None = None,
    baseline_simulations: int | None = None,
    patch_simulations: int = DEFAULT_PATCH_SIMULATIONS,
    seed: int = 42,
    output_path: str | Path | None = "output/patch_impact.csv",
    top10_output_path: str | Path | None = "output/top10_recommendations.csv",
    top_k: int = 10,
) -> pd.DataFrame:
    """Evaluate filtered candidates, reusing one baseline result and write outputs."""
    rows = ranked_vulnerabilities.to_dict("records") if hasattr(ranked_vulnerabilities, "to_dict") else [dict(row) for row in ranked_vulnerabilities]
    critical_asset_ids = list(_criticality_map(critical_assets))
    if baseline_result is None:
        baseline_result = run_baseline_simulation(
            graph,
            vulnerabilities,
            entry_points,
            critical_asset_ids,
            n_simulations=baseline_simulations or 2000,
            seed=seed,
        )
    risk_before = calculate_network_risk(baseline_result, critical_assets)
    candidates = filter_patch_candidates(rows, graph_analysis)
    analysis_features = {item["host_id"]: item for item in (graph_analysis or {}).get("host_features", [])}
    path_data = {item["host_id"]: item for item in (graph_analysis or {}).get("choke_points", [])}
    evaluated = []
    for candidate in candidates:
        candidate = dict(candidate)
        host_id = candidate["host_id"]
        candidate.setdefault("critical_assets_affected", analysis_features.get(host_id, {}).get("reachable_critical_assets", []))
        candidate.setdefault("path_frequency", path_data.get(host_id, {}).get("path_count", 0))
        evaluated.append(evaluate_patch_impact(candidate, baseline_result, graph, vulnerabilities, entry_points, critical_assets, patch_simulations, MAX_ATTACK_STEPS))
    from .ranking import rank_patch_candidates, get_top_10_recommendations
    ranked = rank_patch_candidates(evaluated)
    top10 = get_top_10_recommendations(ranked, top_k=top_k)
    if output_path is not None:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        ranked.to_csv(path, index=False)
    if top10_output_path is not None:
        path = Path(top10_output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        top10.to_csv(path, index=False)
    return ranked
