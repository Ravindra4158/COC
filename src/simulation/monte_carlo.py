from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import logging
from typing import Any

import networkx as nx
import numpy as np

from .attacker import AttackerState, simulate_attack
from .budget import DEFAULT_SIMULATIONS, MAX_ATTACK_STEPS, get_simulation_budget, filter_candidate_vulnerabilities

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


def _normalise_vulnerabilities(vulnerabilities: Any) -> list[dict[str, Any]]:
    if hasattr(vulnerabilities, "to_dict"):
        rows = vulnerabilities.to_dict("records")
    elif isinstance(vulnerabilities, Mapping):
        rows = [dict(value, vuln_id=key) if isinstance(value, Mapping) else {"vuln_id": key, "exploit_probability": value} for key, value in vulnerabilities.items()]
    else:
        rows = [dict(row) for row in vulnerabilities]
    result = []
    for row in rows:
        if "vuln_id" not in row or "host_id" not in row or "exploit_probability" not in row:
            raise ValueError("each vulnerability requires vuln_id, host_id, and exploit_probability")
        probability = float(row["exploit_probability"])
        if not 0 <= probability <= 1:
            raise ValueError(f"exploit probability for {row['vuln_id']} must be between 0 and 1")
        result.append({"vuln_id": row["vuln_id"], "host_id": row["host_id"], "exploit_probability": probability})
    return result


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


def _run_batch(graph, vulnerability_rows, entry_points, critical_assets, simulations, rng, max_steps, accumulator):
    vulnerability_map = _vulnerability_map(vulnerability_rows)
    for _ in range(simulations):
        state = simulate_attack(graph, vulnerability_map, entry_points, set(critical_assets), rng, max_steps)
        _record_trial(accumulator, state, {}, set(critical_assets))


def _result_from_accumulator(accumulator, simulations, seed, stage_1=0, stage_2=0, candidate_count=0):
    critical_probabilities = {asset: count / simulations for asset, count in accumulator["critical_reached"].items()}
    host_statistics = {}
    for host, values in accumulator["hosts"].items():
        host_statistics[host] = {
            **values,
            "compromise_probability": values["times_compromised"] / simulations,
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
    graph: nx.DiGraph,
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
    rng = np.random.Generator(np.random.PCG64(seed))
    accumulator = _new_accumulator(graph, rows, critical_assets)
    logger.info("Running Monte Carlo simulation: simulations=%s seed=%s entries=%s assets=%s", simulations, seed, len(entry_points), len(critical_assets))
    if not any(entry in graph for entry in entry_points):
        return _result_from_accumulator(accumulator, simulations, seed, stage_2=simulations)
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
    return _result_from_accumulator(accumulator, simulations, seed, stage_2=simulations)


def run_two_stage_simulation(
    graph: nx.DiGraph,
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
    _run_batch(graph, candidates, entry_points, critical_assets, screening, rng, max_steps, accumulator)
    _run_batch(graph, candidates, entry_points, critical_assets, simulations - screening, rng, max_steps, accumulator)
    return _result_from_accumulator(accumulator, simulations, seed, stage_1=screening, stage_2=simulations - screening, candidate_count=len(candidates))


def validate_screening_budget(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("screening_simulations must be a positive integer")
    return min(value, 4000)


# Kept importable for callers that want the phase-2 candidate filter without running a simulation.
__all__ = ["MonteCarloResult", "run_baseline_simulation", "run_two_stage_simulation", "simulate_attack"]
