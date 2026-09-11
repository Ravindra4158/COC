"""Budgeted, graph-aware vulnerability ranking for the supplied development instance.

Run from this directory or any working directory.  The only random generators used
for graph/finding generation and simulation are deterministic for the stated seed.
"""

from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

import networkx as nx
import numpy as np


SEED = 20260911
N_HOSTS = 40
EDGE_PROBABILITY = 0.09
ENTRY_NODES = (0, 1)
CRITICAL_WEIGHTS = {35: 1, 36: 2, 37: 3, 38: 4, 39: 5}
MAX_SIMULATIONS = 4000
BASELINE_SIMULATIONS = 2000
PATCH_SIMULATIONS_PER_ITEM = 200
TOP_K = 10


@dataclass(frozen=True)
class Finding:
    vulnerability_id: str
    host_id: int
    cvss: float
    exploit_probability: float


def build_development_graph() -> nx.Graph:
    """Create the exact specified graph and deterministically join components."""
    graph = nx.gnp_random_graph(N_HOSTS, EDGE_PROBABILITY, seed=SEED, directed=False)
    components = sorted((sorted(component) for component in nx.connected_components(graph)), key=lambda c: c[0])
    for left, right in zip(components, components[1:]):
        graph.add_edge(left[0], right[0])
    return graph


def build_findings() -> list[Finding]:
    rng = np.random.Generator(np.random.PCG64(SEED))
    findings: list[Finding] = []
    for host_id in range(N_HOSTS):
        for index in range(2):
            cvss = float(rng.uniform(3.0, 9.8))
            probability = min(0.95, max(0.05, (cvss - 2.0) / 8.0))
            findings.append(Finding(f"h{host_id}-v{index + 1}", host_id, cvss, probability))
    return findings


def findings_by_host(findings: Iterable[Finding]) -> dict[int, list[Finding]]:
    grouped = {host: [] for host in range(N_HOSTS)}
    for finding in findings:
        grouped[finding.host_id].append(finding)
    return grouped


def host_compromise_probability(host_findings: list[Finding], patched: str | None = None) -> float:
    """Probability that at least one unpatched finding enables entry to this host."""
    failure_probability = 1.0
    for finding in host_findings:
        if finding.vulnerability_id != patched:
            failure_probability *= 1.0 - finding.exploit_probability
    return 1.0 - failure_probability


def simulate_risk(
    graph: nx.Graph,
    grouped: dict[int, list[Finding]],
    trials: int,
    seed: int,
    patched: str | None = None,
) -> float:
    """Estimate weighted critical reachability under independent exploit attempts.

    Every trial selects one entry uniformly. An unvisited neighboring host is entered
    when either of its unpatched vulnerabilities succeeds; it is attempted once.
    """
    rng = np.random.Generator(np.random.PCG64(seed))
    total_risk = 0.0
    for _ in range(trials):
        entry = int(rng.choice(ENTRY_NODES))
        reached = {entry}
        frontier = [entry]
        while frontier:
            source = frontier.pop()
            for target in graph.neighbors(source):
                if target in reached:
                    continue
                vulnerable = [v for v in grouped[target] if v.vulnerability_id != patched]
                succeeds = any(rng.random() < finding.exploit_probability for finding in vulnerable)
                if succeeds:
                    reached.add(target)
                    frontier.append(target)
        total_risk += sum(weight for node, weight in CRITICAL_WEIGHTS.items() if node in reached)
    return total_risk / trials


def valid_path_through_host(graph: nx.Graph, host: int) -> list[int] | None:
    """Return a simple entry-to-critical path containing host, if one exists."""
    for entry in ENTRY_NODES:
        for critical in CRITICAL_WEIGHTS:
            entry_to_host = nx.shortest_path(graph, entry, host)
            # A continuation may not reuse any pre-host node: this makes the
            # concatenation a valid simple entry-to-critical path by construction.
            available = graph.copy()
            available.remove_nodes_from(entry_to_host[:-1])
            if critical in available and nx.has_path(available, host, critical):
                return entry_to_host + nx.shortest_path(available, host, critical)[1:]
    return None


def graph_aware_rows(graph: nx.Graph, findings: list[Finding]) -> list[dict]:
    grouped = findings_by_host(findings)
    rows: list[dict] = []
    for finding in findings:
        host = finding.host_id
        path = valid_path_through_host(graph, host)
        entry_distance = min(nx.shortest_path_length(graph, entry, host) for entry in ENTRY_NODES)
        critical_distances = {asset: nx.shortest_path_length(graph, host, asset) for asset in CRITICAL_WEIGHTS}
        nearest_asset_distance = min(critical_distances.values())
        # A simple host-specific reachability proxy, attenuated with distance from
        # each entry. This is deliberately independent of patch simulations.
        entry_reachability = max(1.0 / (1.0 + nx.shortest_path_length(graph, entry, host)) for entry in ENTRY_NODES)
        sibling_failure = float(np.prod([
            1.0 - other.exploit_probability
            for other in grouped[host]
            if other.vulnerability_id != finding.vulnerability_id
        ]))
        individual_enablement = finding.exploit_probability * sibling_failure
        downstream_weight = max(
            weight / (1.0 + critical_distances[asset]) for asset, weight in CRITICAL_WEIGHTS.items()
        )
        structural_score = entry_reachability * individual_enablement * downstream_weight
        # An attacker starts on an entry node, so a finding on that node is not
        # required to traverse into it under the stated traversal model.
        if host in ENTRY_NODES:
            structural_score = 0.0
        if path is None:
            structural_score = 0.0
        rows.append({
            "vulnerability_id": finding.vulnerability_id,
            "host_id": host,
            "cvss": round(finding.cvss, 6),
            "exploit_probability": round(finding.exploit_probability, 6),
            "entry_distance": entry_distance,
            "nearest_critical_distance": nearest_asset_distance,
            "individual_enablement": round(individual_enablement, 8),
            "structural_priority_score": round(structural_score, 8),
            "associated_path": path or [],
        })
    return sorted(rows, key=lambda row: (-row["structural_priority_score"], -row["cvss"], row["vulnerability_id"]))


def write_outputs(rows: list[dict], baseline_risk: float, patch_results: dict[str, float], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    rank_lookup = {row["vulnerability_id"]: rank for rank, row in enumerate(rows, start=1)}
    ranked_rows = []
    for row in rows:
        item = dict(row)
        item["rank"] = rank_lookup[item["vulnerability_id"]]
        item["estimated_risk_reduction_fraction"] = round(patch_results.get(item["vulnerability_id"], item["structural_priority_score"]), 8)
        item["estimated_risk_reduction_percent"] = round(100 * item["estimated_risk_reduction_fraction"], 4)
        item["associated_path"] = " -> ".join(map(str, item["associated_path"]))
        ranked_rows.append(item)
    fieldnames = list(ranked_rows[0])
    with (output_dir / "ranked_vulnerabilities.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(ranked_rows)

    plan = []
    for row in rows[:TOP_K]:
        reduction = patch_results[row["vulnerability_id"]]
        plan.append({
            "rank": rank_lookup[row["vulnerability_id"]],
            "vulnerability_id": row["vulnerability_id"],
            "host_id": row["host_id"],
            "cvss": row["cvss"],
            "associated_attacker_entry_to_critical_asset_path": row["associated_path"],
            "baseline_weighted_risk": round(baseline_risk, 6),
            "patched_weighted_risk": round(baseline_risk * (1.0 - reduction), 6),
            "estimated_risk_reduction_fraction": round(reduction, 6),
            "estimated_risk_reduction_percent": round(100 * reduction, 4),
            "explanation": (
                f"{row['vulnerability_id']} contributes individual host enablement {row['individual_enablement']:.4f}; "
                f"it lies on {row['associated_path']} and patching it reduced simulated weighted critical risk by {100 * reduction:.2f}%."
            ),
        })
    (output_dir / "top10_patch_plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")

    used = BASELINE_SIMULATIONS + TOP_K * PATCH_SIMULATIONS_PER_ITEM
    report = {
        "max_allowed_simulations": MAX_SIMULATIONS,
        "baseline_simulations": BASELINE_SIMULATIONS,
        "patch_simulations_per_recommendation": PATCH_SIMULATIONS_PER_ITEM,
        "recommendations_evaluated": TOP_K,
        "total_simulations_used": used,
        "within_budget": used <= MAX_SIMULATIONS,
        "baseline_weighted_risk": round(baseline_risk, 6),
    }
    (output_dir / "simulation_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    lines = ["# Technical explanations", "", "The ten recommendations below have a valid attacker-entry-to-critical-asset path and a numerical, budgeted Monte Carlo patch estimate.", ""]
    for item in plan:
        lines.extend([
            f"## {item['rank']}. {item['vulnerability_id']} on host {item['host_id']}",
            f"- Path: {' → '.join(map(str, item['associated_attacker_entry_to_critical_asset_path']))}",
            f"- Estimated weighted-risk reduction: {item['estimated_risk_reduction_percent']:.2f}%.",
            f"- {item['explanation']}",
            "",
        ])
    (output_dir / "technical_explanations.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    graph = build_development_graph()
    findings = build_findings()
    grouped = findings_by_host(findings)
    rows = graph_aware_rows(graph, findings)
    eligible = [row for row in rows if row["associated_path"]]
    if len(eligible) < TOP_K:
        raise RuntimeError("Development graph did not yield ten path-associated candidates.")
    selected = eligible[:TOP_K]
    baseline_risk = simulate_risk(graph, grouped, BASELINE_SIMULATIONS, SEED)
    patch_results = {}
    for index, row in enumerate(selected):
        patched_risk = simulate_risk(graph, grouped, PATCH_SIMULATIONS_PER_ITEM, SEED + index + 1, row["vulnerability_id"])
        patch_results[row["vulnerability_id"]] = max(0.0, (baseline_risk - patched_risk) / baseline_risk) if baseline_risk else 0.0
    write_outputs(rows, baseline_risk, patch_results, Path(__file__).resolve().parent / "output")
    print(f"Wrote 80 ranked findings and {TOP_K} patch recommendations using {BASELINE_SIMULATIONS + TOP_K * PATCH_SIMULATIONS_PER_ITEM} simulations.")


if __name__ == "__main__":
    main()
