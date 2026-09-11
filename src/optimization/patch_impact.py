from collections.abc import Iterable, Mapping
from hashlib import sha256
from pathlib import Path
from typing import Any

import numpy as np
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
    return seed


def _evaluate_synchronized_patch_values(
    graph,
    vulnerabilities: Any,
    entry_points: Iterable[Any],
    critical_assets: Any,
    candidate_vuln_ids: set[Any],
    n_sims: int = 2000,
    seed: int = 42,
) -> tuple[float, dict[Any, float]]:
    """Synchronized Monte Carlo evaluation using common random numbers and deciding votes."""
    from collections import defaultdict
    nodes = list(graph.nodes)
    node_to_idx = {n: i for i, n in enumerate(nodes)}
    n_nodes = len(nodes)
    if n_nodes == 0:
        return 0.0, {vid: 0.0 for vid in candidate_vuln_ids}

    entry_indices = [node_to_idx[e] for e in entry_points if e in node_to_idx]
    if not entry_indices:
        return 0.0, {vid: 0.0 for vid in candidate_vuln_ids}

    crit_map = _criticality_map(critical_assets)
    critical_weights = np.zeros(n_nodes, dtype=float)
    for asset, weight in crit_map.items():
        if asset in node_to_idx:
            critical_weights[node_to_idx[asset]] = float(weight)

    from src.simulation.monte_carlo import _normalise_vulnerabilities
    vuln_rows = _normalise_vulnerabilities(vulnerabilities)
    n_v = len(vuln_rows)
    if n_v == 0:
        return 0.0, {vid: 0.0 for vid in candidate_vuln_ids}

    probs = np.array([float(r["exploit_probability"]) for r in vuln_rows])
    vid_to_idx = {r["vuln_id"]: i for i, r in enumerate(vuln_rows)}
    host_vuln_idx: dict[int, list[int]] = defaultdict(list)
    for i, r in enumerate(vuln_rows):
        h_node = r["host_id"]
        if h_node in node_to_idx:
            host_vuln_idx[node_to_idx[h_node]].append(i)

    rng = np.random.Generator(np.random.PCG64(seed))
    draws = rng.random((n_sims, n_v))
    entries = rng.integers(0, len(entry_indices), size=n_sims)
    success = draws < probs

    host_ok = np.zeros((n_sims, n_nodes), dtype=bool)
    for h_idx, idxs in host_vuln_idx.items():
        host_ok[:, h_idx] = success[:, idxs].any(axis=1)

    adj: list[list[int]] = [[] for _ in range(n_nodes)]
    is_directed = graph.is_directed()
    for u in nodes:
        nbrs = graph.successors(u) if is_directed else graph.neighbors(u)
        adj[node_to_idx[u]] = [node_to_idx[v] for v in nbrs if v in node_to_idx]

    def _bfs_risk(t: int, mask: np.ndarray) -> float:
        entry = entry_indices[entries[t]]
        comp = {entry}
        queue = [entry]
        qi = 0
        while qi < len(queue):
            u = queue[qi]
            qi += 1
            for nb in adj[u]:
                if nb not in comp and mask[nb]:
                    comp.add(nb)
                    queue.append(nb)
        return float(sum(critical_weights[c] for c in comp if critical_weights[c] > 0))

    baseline_risks = np.empty(n_sims)
    for t in range(n_sims):
        baseline_risks[t] = _bfs_risk(t, host_ok[t])
    baseline_risk = float(baseline_risks.mean())

    deciding = np.zeros((n_sims, n_v), dtype=bool)
    for h_idx, idxs in host_vuln_idx.items():
        for vi in idxs:
            others = [j for j in idxs if j != vi]
            w = success[:, others].any(axis=1) if others else np.zeros(n_sims, dtype=bool)
            deciding[:, vi] = host_ok[:, h_idx] & ~w

    patch_values: dict[Any, float] = {}
    entry_set = set(entry_indices)
    for vid in candidate_vuln_ids:
        if vid not in vid_to_idx:
            patch_values[vid] = 0.0
            continue
        vi = vid_to_idx[vid]
        r = vuln_rows[vi]
        h_idx = node_to_idx.get(r["host_id"])
        if h_idx in entry_set:
            patch_values[vid] = 0.0
            continue
        affected = np.where(deciding[:, vi])[0]
        if len(affected) == 0:
            patch_values[vid] = 0.0
            continue
        patched_risks = baseline_risks.copy()
        for t in affected:
            mask = host_ok[t].copy()
            mask[h_idx] = False
            patched_risks[t] = _bfs_risk(t, mask)
        patch_values[vid] = max(0.0, baseline_risk - float(patched_risks.mean()))

    return baseline_risk, patch_values


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
        seed=baseline_seed,
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
    """Evaluate filtered candidates using Synchronized Monte Carlo with CRN and write outputs."""
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
    baseline_seed = int(_field(baseline_result, "seed", seed))
    sim_budget = min(4000, max(200, baseline_result.simulations))
    candidates = filter_patch_candidates(rows, graph_analysis)
    analysis_features = {item["host_id"]: item for item in (graph_analysis or {}).get("host_features", [])}
    path_data = {item["host_id"]: item for item in (graph_analysis or {}).get("choke_points", [])}

    candidate_ids = {c.get("vulnerability_id", c.get("vuln_id")) for c in candidates}
    baseline_risk, sync_patch_values = _evaluate_synchronized_patch_values(
        graph,
        vulnerabilities,
        entry_points,
        critical_assets,
        candidate_ids,
        n_sims=sim_budget,
        seed=baseline_seed,
    )

    evaluated = []
    for candidate in candidates:
        candidate = dict(candidate)
        host_id = candidate["host_id"]
        vid = candidate.get("vulnerability_id", candidate.get("vuln_id"))
        candidate.setdefault("critical_assets_affected", analysis_features.get(host_id, {}).get("reachable_critical_assets", []))
        candidate.setdefault("path_frequency", path_data.get(host_id, {}).get("path_count", 0))

        if vid in sync_patch_values:
            pv = sync_patch_values[vid]
            risk_after = max(0.0, baseline_risk - pv)
            reduc_pct = (pv / baseline_risk * 100.0) if baseline_risk > 0 else 0.0
            res = dict(candidate)
            res.update({
                "vulnerability_id": vid,
                "risk_before": baseline_risk,
                "risk_after": risk_after,
                "patch_value": pv,
                "risk_reduction_percent": reduc_pct,
                "critical_assets_affected": list(candidate.get("critical_assets_affected", [])),
                "attack_path_count": int(candidate.get("path_frequency", 0)),
                "patch_priority_score": pv,
            })
            if "patch_cost" in candidate and candidate["patch_cost"] not in (None, ""):
                cost = float(candidate["patch_cost"])
                if cost > 0:
                    res["patch_efficiency"] = pv / cost
            evaluated.append(res)
        else:
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
