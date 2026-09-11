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
    """Run one BFS-flood attack trial.

    The attacker starts on a random entry node. Each step, ALL uncompromised
    neighbors of any compromised host are tested. A host is entered when at
    least one of its unpatched vulnerabilities succeeds (independent draws).
    To keep the RNG stream deterministic regardless of disabled vulns, a
    random value is always consumed for every vulnerability on every
    attempted host.
    """
    valid_entries = [entry for entry in entry_points if entry in graph]
    if not valid_entries:
        raise ValueError("at least one valid attacker entry point is required")
    if max_steps <= 0:
        raise ValueError("max_steps must be positive")

    disabled_vulnerabilities = disabled_vulnerabilities or set()
    entry_point = valid_entries[int(rng.integers(0, len(valid_entries)))]
    state = AttackerState(
        current_host=entry_point,
        entry_points={entry_point},
        compromised_hosts={entry_point},
    )

    neighbor_fn = graph.successors if graph.is_directed() else graph.neighbors

    for _ in range(max_steps):
        state.reached_critical_assets.update(state.compromised_hosts & critical_assets)
        if critical_assets and state.reached_critical_assets == critical_assets:
            break

        # BFS flood: collect ALL uncompromised neighbors of any compromised host.
        frontier = sorted(
            {
                neighbor
                for host in state.compromised_hosts
                for neighbor in neighbor_fn(host)
                if neighbor not in state.compromised_hosts
            },
            key=str,
        )
        if not frontier:
            break

        newly_compromised = False
        for target in frontier:
            target_vulnerabilities = graph.nodes[target].get("vulnerabilities", [])

            # A host with no vulnerabilities at all is freely traversable.
            if not target_vulnerabilities:
                state.compromised_hosts.add(target)
                state.current_host = target
                newly_compromised = True
                continue

            # Draw a random value for EVERY vulnerability on the target host
            # to keep the RNG stream synchronized regardless of which vulns
            # are disabled (critical for accurate patch-value estimation).
            target_compromised = False
            for vulnerability_id in target_vulnerabilities:
                state.attempted_exploits.add(vulnerability_id)
                roll = rng.random()
                if vulnerability_id in disabled_vulnerabilities:
                    continue
                vulnerability = vulnerabilities.get(vulnerability_id)
                if vulnerability is None:
                    continue
                if roll < vulnerability["exploit_probability"]:
                    state.successful_exploits.add(vulnerability_id)
                    target_compromised = True
                else:
                    state.failed_exploits.add(vulnerability_id)

            if target_compromised:
                state.compromised_hosts.add(target)
                state.current_host = target
                newly_compromised = True

        if not newly_compromised:
            break

    state.reached_critical_assets.update(state.compromised_hosts & critical_assets)
    return state
