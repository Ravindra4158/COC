"""Unified Monte Carlo attack simulation and synchronized counterfactual evaluation."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import logging
from typing import Any

import networkx as nx
import numpy as np

from .attacker import AttackerState, simulate_attack
from .budget import DEFAULT_SIMULATIONS, MAX_ATTACK_STEPS, get_simulation_budget, filter_candidate_vulnerabilities
from src.data.loader import parse_seed

logger = logging.getLogger(__name__)


@dataclass(eq=True)
class MonteCarloResult:
    simulations: int
    seed: int
    critical_asset_reach_probability: float
    critical_asset_probabilities: dict[Any, float]
    host_statistics: dict[Any, dict[str, float | int]]
    vulnerability_statistics: dict[Any, dict[str, float | int]]
    stage_1_simulations: int = 0
    stage_2_simulations: int = 0
    candidate_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "simulations": self.simulations,
            "seed": self.seed,
            "critical_asset_reach_probability": self.critical_asset_reach_probability,
            "critical_asset_probabilities": self.critical_asset_probabilities,
            "host_statistics": self.host_statistics,
            "vulnerability_statistics": self.vulnerability_statistics,
            "stage_1_simulations": self.stage_1_simulations,
            "stage_2_simulations": self.stage_2_simulations,
            "candidate_count": self.candidate_count,
            "total_simulations": self.simulations,
        }


@dataclass
class SynchronizedEvaluationResult:
    baseline_risk: float
    patch_values: dict[str, float]
    critical_asset_probabilities: dict[Any, float]
    critical_asset_reach_probability: float
    host_compromise_probabilities: dict[Any, float]
    host_causal_frequencies: dict[Any, float]
    vulnerability_enablement: dict[str, float]
    total_simulations: int
    seed: int


def _normalise_vulnerabilities(vulnerabilities: Any) -> list[dict[str, Any]]:
    if hasattr(vulnerabilities, "to_dict"):
        rows = vulnerabilities.to_dict("records")
    elif isinstance(vulnerabilities, Mapping):
        rows = [
            dict(value, vuln_id=key) if isinstance(value, Mapping) else {"vuln_id": key, "exploit_probability": value}
            for key, value in vulnerabilities.items()
        ]
    else:
        rows = [dict(row) for row in vulnerabilities]
    result = []
    for row in rows:
        vid = row.get("vuln_id", row.get("vulnerability_id"))
        if vid is None or "host_id" not in row:
            raise ValueError("each vulnerability requires vuln_id and host_id")
        probability = row.get("exploit_probability")
        if probability is None or (isinstance(probability, float) and np.isnan(probability)):
            if "cvss" in row and row["cvss"] is not None:
                probability = min(0.95, max(0.05, (float(row["cvss"]) - 2.0) / 8.0))
            else:
                raise ValueError(f"vulnerability {vid} requires exploit_probability or cvss")
        probability = float(probability)
        if not 0 <= probability <= 1:
            raise ValueError(f"exploit probability for {vid} must be between 0 and 1")
        result.append({
            "vuln_id": vid,
            "vulnerability_id": vid,
            "host_id": row["host_id"],
            "cvss": float(row.get("cvss", 5.0)),
            "exploit_probability": probability,
        })
    return result


def _criticality_map(critical_assets: Any) -> dict[Any, float]:
    if hasattr(critical_assets, "to_dict"):
        return {
            row["host_id"]: float(row.get("criticality", row.get("impact_weight", 1.0)))
            for row in critical_assets.to_dict("records")
        }
    if isinstance(critical_assets, Mapping):
        return {asset: float(value) for asset, value in critical_assets.items()}
    return {asset: 1.0 for asset in critical_assets}


def _vulnerability_map(rows: Iterable[Mapping[str, Any]]) -> dict[Any, dict[str, Any]]:
    return {row["vuln_id"]: dict(row) for row in rows}


def _new_accumulator(graph, vulnerability_rows, critical_assets):
    return {
        "critical_reached": {asset: 0 for asset in critical_assets},
        "any_critical": 0,
        "hosts": {host: {"times_compromised": 0, "times_used_in_successful_attack": 0} for host in graph.nodes},
        "vulnerabilities": {
            row["vuln_id"]: {
                "attempt_count": 0,
                "success_count": 0,
                "configured_probability": row["exploit_probability"],
            }
            for row in vulnerability_rows
        },
    }


def _record_trial(accumulator, state: AttackerState, vulnerable_hosts: dict[Any, list[Any]], critical_assets: set[Any]) -> None:
    for host in state.compromised_hosts:
        if host in accumulator["hosts"]:
            accumulator["hosts"][host]["times_compromised"] += 1
    if state.reached_critical_assets:
        accumulator["any_critical"] += 1
        for host in state.compromised_hosts:
            if host in accumulator["hosts"]:
                accumulator["hosts"][host]["times_used_in_successful_attack"] += 1
    for vulnerability_id in state.attempted_exploits:
        if vulnerability_id in accumulator["vulnerabilities"]:
            accumulator["vulnerabilities"][vulnerability_id]["attempt_count"] += 1
    for vulnerability_id in state.successful_exploits:
        if vulnerability_id in accumulator["vulnerabilities"]:
            accumulator["vulnerabilities"][vulnerability_id]["success_count"] += 1
    for asset in critical_assets & state.reached_critical_assets:
        accumulator["critical_reached"][asset] += 1


def _result_from_accumulator(accumulator, simulations, seed, stage_1=0, stage_2=0, candidate_count=0):
    critical_probabilities = {asset: count / simulations for asset, count in accumulator["critical_reached"].items()}
    host_statistics = {}
    for host, values in accumulator["hosts"].items():
        host_statistics[host] = {
            **values,
            "compromise_probability": values["times_compromised"] / simulations,
            "causal_frequency": values["times_used_in_successful_attack"] / simulations,
        }
    vulnerability_statistics = {}
    for vulnerability_id, values in accumulator["vulnerabilities"].items():
        attempts = values["attempt_count"]
        vulnerability_statistics[vulnerability_id] = {
            **values,
            "observed_success_probability": values["success_count"] / attempts if attempts else 0.0,
        }
    return MonteCarloResult(
        simulations=simulations,
        seed=seed,
        critical_asset_reach_probability=accumulator["any_critical"] / simulations,
        critical_asset_probabilities=critical_probabilities,
        host_statistics=host_statistics,
        vulnerability_statistics=vulnerability_statistics,
        stage_1_simulations=stage_1,
        stage_2_simulations=stage_2,
        candidate_count=candidate_count,
    )


def run_baseline_simulation(
    graph: nx.Graph | nx.DiGraph,
    vulnerabilities: Any,
    entry_points: Iterable[Any],
    critical_assets: Iterable[Any],
    n_simulations: int = DEFAULT_SIMULATIONS,
    seed: int = 42,
    max_steps: int = MAX_ATTACK_STEPS,
    disabled_vulnerabilities: set[Any] | None = None,
) -> MonteCarloResult:
    """Run a reproducible, budget-bounded Monte Carlo attack simulation."""
    simulations = get_simulation_budget(n_simulations)
    entry_points = list(entry_points)
    critical_assets = list(critical_assets)
    rows = _normalise_vulnerabilities(vulnerabilities)
    int_seed = parse_seed(seed, 42)
    rng = np.random.Generator(np.random.PCG64(int_seed))
    accumulator = _new_accumulator(graph, rows, critical_assets)
    logger.info("Running baseline simulation: simulations=%s seed=%s entries=%s assets=%s", simulations, int_seed, len(entry_points), len(critical_assets))
    if not any(entry in graph for entry in entry_points):
        return _result_from_accumulator(accumulator, simulations, int_seed, stage_2=simulations)
    vulnerability_map = _vulnerability_map(rows)
    for _ in range(simulations):
        state = simulate_attack(
            graph,
            vulnerability_map,
            entry_points,
            set(critical_assets),
            rng,
            max_steps,
            disabled_vulnerabilities,
        )
        _record_trial(accumulator, state, {}, set(critical_assets))
    return _result_from_accumulator(accumulator, simulations, int_seed, stage_2=simulations)


def evaluate_synchronized_monte_carlo(
    graph: nx.Graph | nx.DiGraph,
    vulnerabilities: Any,
    entry_points: Iterable[Any],
    critical_assets: Any,
    candidate_vuln_ids: set[Any] | None = None,
    n_sims: int = 4000,
    seed: int | str | None = 20260911,
) -> SynchronizedEvaluationResult:
    """High-performance Synchronized Monte Carlo with Common Random Numbers (CRN).

    Pre-draws random exploit outcome matrices to evaluate baseline risk and all
    single-vulnerability counterfactual patch scenarios with zero Monte Carlo variance.
    """
    int_seed = parse_seed(seed, 20260911)
    nodes = list(graph.nodes)
    node_to_idx = {n: i for i, n in enumerate(nodes)}
    n_nodes = len(nodes)
    if n_nodes == 0:
        return SynchronizedEvaluationResult(
            baseline_risk=0.0,
            patch_values={},
            critical_asset_probabilities={},
            critical_asset_reach_probability=0.0,
            host_compromise_probabilities={},
            host_causal_frequencies={},
            vulnerability_enablement={},
            total_simulations=0,
            seed=int_seed,
        )

    entry_indices = [node_to_idx[e] for e in entry_points if e in node_to_idx]
    if not entry_indices:
        return SynchronizedEvaluationResult(
            baseline_risk=0.0,
            patch_values={},
            critical_asset_probabilities={},
            critical_asset_reach_probability=0.0,
            host_compromise_probabilities={n: 0.0 for n in nodes},
            host_causal_frequencies={n: 0.0 for n in nodes},
            vulnerability_enablement={},
            total_simulations=0,
            seed=int_seed,
        )

    crit_map = _criticality_map(critical_assets)
    critical_weights = np.zeros(n_nodes, dtype=float)
    critical_indices = []
    for asset, weight in crit_map.items():
        if asset in node_to_idx:
            idx = node_to_idx[asset]
            critical_weights[idx] = float(weight)
            critical_indices.append(idx)
    critical_idx_set = set(critical_indices)

    vuln_rows = _normalise_vulnerabilities(vulnerabilities)
    n_v = len(vuln_rows)
    if n_v == 0:
        return SynchronizedEvaluationResult(
            baseline_risk=0.0,
            patch_values={},
            critical_asset_probabilities={asset: 0.0 for asset in crit_map},
            critical_asset_reach_probability=0.0,
            host_compromise_probabilities={n: 0.0 for n in nodes},
            host_causal_frequencies={n: 0.0 for n in nodes},
            vulnerability_enablement={},
            total_simulations=n_sims,
            seed=int_seed,
        )

    vid_to_idx = {r["vuln_id"]: i for i, r in enumerate(vuln_rows)}
    probs = np.array([float(r["exploit_probability"]) for r in vuln_rows])

    # Map each host to its vulnerability indices
    host_vuln_idx: dict[int, list[int]] = defaultdict(list)
    host_vulns_map: dict[Any, list[dict[str, Any]]] = defaultdict(list)
    for i, r in enumerate(vuln_rows):
        h_node = r["host_id"]
        host_vulns_map[h_node].append(r)
        if h_node in node_to_idx:
            host_vuln_idx[node_to_idx[h_node]].append(i)

    # Calculate marginal enablement ΔP_comp for each vulnerability
    vulnerability_enablement: dict[str, float] = {}
    for r in vuln_rows:
        h = r["host_id"]
        siblings = [o for o in host_vulns_map[h] if o["vuln_id"] != r["vuln_id"]]
        sibling_fail = float(np.prod([1.0 - float(s["exploit_probability"]) for s in siblings])) if siblings else 1.0
        vulnerability_enablement[r["vuln_id"]] = float(r["exploit_probability"]) * sibling_fail

    # Pre-draw all randomness
    rng = np.random.Generator(np.random.PCG64(int_seed))
    draws = rng.random((n_sims, n_v))
    entries = rng.integers(0, len(entry_indices), size=n_sims)
    success = draws < probs

    # Determine per-trial host compromise status
    host_ok = np.zeros((n_sims, n_nodes), dtype=bool)
    for h_idx, idxs in host_vuln_idx.items():
        host_ok[:, h_idx] = success[:, idxs].any(axis=1)

    # Build adjacency list
    adj: list[list[int]] = [[] for _ in range(n_nodes)]
    is_directed = graph.is_directed()
    for u in nodes:
        nbrs = graph.successors(u) if is_directed else graph.neighbors(u)
        adj[node_to_idx[u]] = [node_to_idx[v] for v in nbrs if v in node_to_idx]

    # BFS helper
    def _bfs_sim(t: int, mask: np.ndarray) -> tuple[float, set[int]]:
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
        risk = float(sum(critical_weights[c] for c in comp if critical_weights[c] > 0))
        return risk, comp

    # Baseline evaluation across all trials
    baseline_risks = np.empty(n_sims)
    crit_reached_counts = {asset: 0 for asset in crit_map}
    any_crit_count = 0
    host_comp_counts = np.zeros(n_nodes, dtype=int)
    host_causal_counts = np.zeros(n_nodes, dtype=int)

    for t in range(n_sims):
        risk, comp = _bfs_sim(t, host_ok[t])
        baseline_risks[t] = risk
        for h_i in comp:
            host_comp_counts[h_i] += 1
        reached_crits = comp & critical_idx_set
        if reached_crits:
            any_crit_count += 1
            for c_i in reached_crits:
                asset_name = nodes[c_i]
                crit_reached_counts[asset_name] = crit_reached_counts.get(asset_name, 0) + 1
            for h_i in comp:
                host_causal_counts[h_i] += 1

    baseline_risk = float(baseline_risks.mean())

    # Deciding vote mask: deciding[t, vi] == True iff host is compromised ONLY due to vi
    deciding = np.zeros((n_sims, n_v), dtype=bool)
    for h_idx, idxs in host_vuln_idx.items():
        for vi in idxs:
            others = [j for j in idxs if j != vi]
            w = success[:, others].any(axis=1) if others else np.zeros(n_sims, dtype=bool)
            deciding[:, vi] = host_ok[:, h_idx] & ~w

    # Evaluate patches
    eval_target_ids = candidate_vuln_ids if candidate_vuln_ids is not None else {r["vuln_id"] for r in vuln_rows}
    entry_set = set(entry_indices)
    patch_values: dict[str, float] = {}

    for vid in eval_target_ids:
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
            r_val, _ = _bfs_sim(t, mask)
            patched_risks[t] = r_val
        patch_values[vid] = max(0.0, baseline_risk - float(patched_risks.mean()))

    crit_probs = {asset: count / n_sims for asset, count in crit_reached_counts.items()}
    host_comp_probs = {nodes[i]: float(host_comp_counts[i]) / n_sims for i in range(n_nodes)}
    host_causal_freqs = {nodes[i]: float(host_causal_counts[i]) / n_sims for i in range(n_nodes)}

    return SynchronizedEvaluationResult(
        baseline_risk=baseline_risk,
        patch_values=patch_values,
        critical_asset_probabilities=crit_probs,
        critical_asset_reach_probability=any_crit_count / n_sims,
        host_compromise_probabilities=host_comp_probs,
        host_causal_frequencies=host_causal_freqs,
        vulnerability_enablement=vulnerability_enablement,
        total_simulations=n_sims,
        seed=seed,
    )


def run_two_stage_simulation(
    graph: nx.Graph | nx.DiGraph,
    vulnerabilities: Any,
    entry_points: Iterable[Any],
    critical_assets: Iterable[Any],
    n_simulations: int = DEFAULT_SIMULATIONS,
    seed: int = 42,
    screening_simulations: int = 500,
    max_steps: int = MAX_ATTACK_STEPS,
) -> MonteCarloResult:
    """Screen deterministic candidates first, then spend the remaining budget on them."""
    simulations = get_simulation_budget(n_simulations)
    screening = min(validate_screening_budget(screening_simulations), simulations)
    entry_points = list(entry_points)
    critical_assets = list(critical_assets)
    rows = _normalise_vulnerabilities(vulnerabilities)
    candidates = filter_candidate_vulnerabilities(graph, rows, entry_points, critical_assets)
    rng = np.random.Generator(np.random.PCG64(seed))
    accumulator = _new_accumulator(graph, rows, critical_assets)
    if not any(entry in graph for entry in entry_points):
        return _result_from_accumulator(accumulator, simulations, seed, stage_1=screening, stage_2=simulations - screening, candidate_count=len(candidates))
    vulnerability_map = _vulnerability_map(candidates)
    for _ in range(screening):
        state = simulate_attack(graph, vulnerability_map, entry_points, set(critical_assets), rng, max_steps)
        _record_trial(accumulator, state, {}, set(critical_assets))
    for _ in range(simulations - screening):
        state = simulate_attack(graph, vulnerability_map, entry_points, set(critical_assets), rng, max_steps)
        _record_trial(accumulator, state, {}, set(critical_assets))
    return _result_from_accumulator(accumulator, simulations, seed, stage_1=screening, stage_2=simulations - screening, candidate_count=len(candidates))


def validate_screening_budget(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("screening_simulations must be a positive integer")
    return min(value, 4000)


__all__ = [
    "MonteCarloResult",
    "SynchronizedEvaluationResult",
    "evaluate_synchronized_monte_carlo",
    "run_baseline_simulation",
    "run_two_stage_simulation",
    "simulate_attack",
]
