from dataclasses import dataclass, field
from typing import Any

import networkx as nx
import numpy as np


@dataclass
class AttackerState:
    """Mutable state for one bounded attacker trial."""

    current_host: Any
    entry_points: set[Any] = field(default_factory=set)
    compromised_hosts: set[Any] = field(default_factory=set)
    reached_critical_assets: set[Any] = field(default_factory=set)
    successful_exploits: set[Any] = field(default_factory=set)
    failed_exploits: set[Any] = field(default_factory=set)
    attempted_exploits: set[Any] = field(default_factory=set)


def simulate_attack(
    graph: nx.DiGraph,
    vulnerabilities: dict[Any, dict[str, Any]],
    entry_points: list[Any],
    critical_assets: set[Any],
    rng: np.random.Generator,
    max_steps: int = 50,
    disabled_vulnerabilities: set[Any] | None = None,
) -> AttackerState:
    """Run one directed attack trial using each vulnerability at most once."""
    valid_entries = [entry for entry in entry_points if entry in graph]
    if not valid_entries:
        raise ValueError("at least one valid attacker entry point is required")
    if max_steps <= 0:
        raise ValueError("max_steps must be positive")

    disabled_vulnerabilities = disabled_vulnerabilities or set()
    entry_point = valid_entries[int(rng.integers(0, len(valid_entries)))]
    state = AttackerState(current_host=entry_point, entry_points={entry_point}, compromised_hosts={entry_point})
    blocked_hosts: set[Any] = set()
    for _ in range(max_steps):
        state.reached_critical_assets.update(state.compromised_hosts & critical_assets)
        if critical_assets and state.reached_critical_assets == critical_assets:
            break
        neighbor_fn = graph.successors if graph.is_directed() else graph.neighbors
        frontier = sorted(
            {
                neighbor
                for host in state.compromised_hosts
                for neighbor in neighbor_fn(host)
                if neighbor not in state.compromised_hosts and neighbor not in blocked_hosts
            },
            key=str,
        )
        if not frontier:
            break
        target = frontier[int(rng.integers(0, len(frontier)))]
        target_vulnerabilities = graph.nodes[target].get("vulnerabilities", [])
        active_vulnerabilities = [
            vulnerability_id
            for vulnerability_id in target_vulnerabilities
            if vulnerability_id not in disabled_vulnerabilities
        ]
        # A host with vulnerabilities still requires exploitation even when all
        # of those vulnerabilities are temporarily disabled.
        target_compromised = not target_vulnerabilities
        for vulnerability_id in active_vulnerabilities:
            if vulnerability_id in state.attempted_exploits:
                continue
            state.attempted_exploits.add(vulnerability_id)
            vulnerability = vulnerabilities.get(vulnerability_id)
            if vulnerability is None:
                continue
            if rng.random() < vulnerability["exploit_probability"]:
                state.successful_exploits.add(vulnerability_id)
                target_compromised = True
                break
            state.failed_exploits.add(vulnerability_id)
        if target_compromised:
            state.compromised_hosts.add(target)
            state.current_host = target
        else:
            blocked_hosts.add(target)
    state.reached_critical_assets.update(state.compromised_hosts & critical_assets)
    return state
