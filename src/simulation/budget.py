from collections.abc import Iterable, Mapping
from typing import Any

from src.graph.analysis import calculate_downstream_critical_assets
from src.graph.paths import get_reachable_nodes_from_entries

MAX_SIMULATIONS = 4000
DEFAULT_SIMULATIONS = 2000
EXPLORATORY_SIMULATIONS = 500
MAX_ATTACK_STEPS = 50


def validate_simulation_budget(requested: int) -> int:
    """Validate and clamp a requested simulation count to the hard maximum."""
    if isinstance(requested, bool) or not isinstance(requested, int) or requested <= 0:
        raise ValueError("simulation count must be a positive integer")
    return min(requested, MAX_SIMULATIONS)


def get_simulation_budget(requested: int | None = None, confidence: str = "normal") -> int:
    """Return an exploratory, normal, or high-confidence bounded budget."""
    if requested is not None:
        return validate_simulation_budget(requested)
    budgets = {
        "exploratory": EXPLORATORY_SIMULATIONS,
        "normal": DEFAULT_SIMULATIONS,
        "high": MAX_SIMULATIONS,
    }
    if confidence not in budgets:
        raise ValueError(f"unknown confidence level: {confidence}")
    return budgets[confidence]


def filter_candidate_vulnerabilities(
    graph,
    vulnerabilities: Iterable[Mapping[str, Any]],
    entry_points: Iterable[Any],
    critical_assets: Iterable[Any],
) -> list[Mapping[str, Any]]:
    """Keep vulnerabilities on reachable hosts with a downstream critical asset."""
    reachable = get_reachable_nodes_from_entries(graph, entry_points)
    downstream = calculate_downstream_critical_assets(graph, critical_assets)
    return [
        vulnerability
        for vulnerability in vulnerabilities
        if vulnerability["host_id"] in reachable and downstream.get(vulnerability["host_id"])
    ]
