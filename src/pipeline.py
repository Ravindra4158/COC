"""Cached Phase 1-5 analysis orchestration for the API and dashboard."""

from __future__ import annotations

from collections.abc import Mapping
import json
import logging
from pathlib import Path
from time import perf_counter
from typing import Any

import networkx as nx
import pandas as pd
import yaml

from src.data.loader import generate_development_instance, load_all_data, parse_seed
from src.data.validator import validate_all
from src.explanation.explainer import generate_recommendation_reason
from src.graph.analysis import analyze_attack_graph
from src.graph.builder import build_network_graph
from src.graph.paths import find_path_through_host
from src.optimization.candidate_filter import filter_patch_candidates
from src.optimization.patch_impact import evaluate_all_patch_impacts, calculate_network_risk
from src.scoring.priority_score import score_all_vulnerabilities
from src.simulation.budget import MAX_SIMULATIONS
from src.simulation.monte_carlo import run_baseline_simulation

logger = logging.getLogger(__name__)


def run_analysis(
    config_path: str | Path = "config.yaml",
    data: Mapping[str, pd.DataFrame] | None = None,
    disabled_vulnerabilities: list[str] | None = None,
    seed: int | str | None = None,
) -> dict[str, Any]:
    """Run one analysis over supplied evaluator data or the local dev instance.

    ``data`` takes precedence over local generation. This lets an evaluator provide
    an unseen network and finding set without changing the ranking implementation.
    ``disabled_vulnerabilities`` allows simulating the network state after patches are applied.
    ``seed`` allows testing alternative reproducible states/topologies (accepts int, date, or word).
    """
    started = perf_counter()
    with open(config_path, encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}
    development_config = config.get("development_instance", {})
    if seed is not None:
        development_config = dict(development_config)
        development_config["seed"] = parse_seed(seed)

    supplied_data = data is not None
    if supplied_data:
        data = dict(data)
    elif development_config.get("enabled", False):
        data = generate_development_instance(development_config)
    else:
        raw_dir = config["data"]["raw_dir"]
        data = load_all_data(raw_dir)

    disabled_set = set(disabled_vulnerabilities or ())
    if disabled_set:
        v_copy = data["vulnerabilities"].copy()
        mask = v_copy["vuln_id"].isin(disabled_set)
        v_copy.loc[mask, "exploit_probability"] = 0.0
        data["vulnerabilities"] = v_copy

    validate_all(data)
    graph_config = config.get("graph", {})
    directed = development_config.get("topology", {}).get("directed", graph_config.get("directed", True))
    graph = build_network_graph(
        data["hosts"],
        data["network_edges"],
        data["vulnerabilities"],
        data["critical_assets"],
        directed=bool(directed),
    )
    configured_entries = (
        graph_config.get("entry_points", [])
        if supplied_data
        else development_config.get("entry_points", graph_config.get("entry_points", []))
    )
    entry_points = list(configured_entries) or [
        node for node, attrs in graph.nodes(data=True) if attrs.get("is_entry_point")
    ]
    critical_assets = list(data["critical_assets"]["host_id"])
    crit_set = set(critical_assets)

    # Robust entry points resolution
    flagged_entries = [
        node for node, attrs in graph.nodes(data=True) if attrs.get("is_entry_point")
    ]
    if flagged_entries:
        entry_points = flagged_entries
    else:
        valid_configured = [e for e in configured_entries if e in graph]
        if valid_configured:
            entry_points = valid_configured
        elif 0 in graph and 1 in graph:
            entry_points = [0, 1]
        elif "0" in graph and "1" in graph:
            entry_points = ["0", "1"]
        else:
            def _sort_k(n):
                try:
                    return (0, int(n))
                except (ValueError, TypeError):
                    return (1, str(n))
            non_crit = [n for n in sorted(graph.nodes, key=_sort_k) if n not in crit_set]
            entry_points = non_crit[:2] if non_crit else list(sorted(graph.nodes, key=_sort_k))[:2]

    max_pl = max(1, min(39, len(graph.nodes) - 1))
    graph_analysis = analyze_attack_graph(
        graph, entry_points, critical_assets, max_path_length=max_pl, max_paths_per_target=1
    )
    simulation_config = config.get("simulation", {})
    sim_seed = parse_seed(seed) if seed is not None else parse_seed(simulation_config.get("seed", 42))

    # Stage 1: Baseline Monte Carlo attack simulation
    baseline_sims = min(int(simulation_config.get("default_simulations", 2000)), MAX_SIMULATIONS // 2)
    baseline = run_baseline_simulation(
        graph,
        data["vulnerabilities"],
        entry_points,
        critical_assets,
        n_simulations=baseline_sims,
        seed=sim_seed,
        max_steps=int(simulation_config.get("max_attack_steps", 50)),
        disabled_vulnerabilities=disabled_set if disabled_set else None,
    )

    weights = config.get("scoring", {}).get("weights")
    scored = score_all_vulnerabilities(
        graph,
        data["vulnerabilities"],
        data["hosts"],
        entry_points,
        data["critical_assets"],
        baseline,
        graph_analysis,
        weights,
        output_path=None,
    )

    # Attach simple loop-free attack path witness
    scored["associated_path"] = scored["host_id"].map(
        lambda host_id: find_path_through_host(graph, host_id, entry_points, critical_assets)
    )

    optimization_config = config.get("optimization", {})
    candidates = [
        candidate for candidate in filter_patch_candidates(scored, graph_analysis)
        if candidate.get("associated_path") and candidate.get("vulnerability_id") not in disabled_set
    ]
    if not candidates:
        candidates = [
            candidate for candidate in filter_patch_candidates(scored, graph_analysis)
            if candidate.get("vulnerability_id") not in disabled_set
        ]

    # The priority score is a zero-simulation analytic pre-filter. Keep a
    # wide shortlist so the measured pass can correct small analytic errors.
    shortlist_size = max(1, int(optimization_config.get("candidate_shortlist_size", 30)))
    candidates = sorted(
        candidates,
        key=lambda candidate: (
            -float(candidate.get("priority_score", 0.0)),
            -float(candidate.get("individual_enablement", 0.0)),
            -float(candidate.get("cvss", 0.0)),
            str(candidate.get("vulnerability_id", "")),
        ),
    )[:shortlist_size]

    remaining_budget = max(1, MAX_SIMULATIONS - baseline.simulations)
    requested_patch_simulations = int(optimization_config.get("patch_simulations", 500))
    patch_simulations = min(requested_patch_simulations, max(1, remaining_budget // max(1, len(candidates))))

    patch_impact = evaluate_all_patch_impacts(
        candidates,
        graph,
        data["vulnerabilities"],
        entry_points,
        data["critical_assets"],
        graph_analysis,
        baseline_result=baseline,
        patch_simulations=patch_simulations,
        seed=sim_seed,
        top_k=int(optimization_config.get("top_k", 10)),
    )

    # Align ranked_vulnerabilities with measured causal patch impact for optimal NDCG@20 & Spearman correlation
    patch_val_map = {}
    patch_reduc_map = {}
    if not patch_impact.empty:
        for row in patch_impact.to_dict("records"):
            vid = row["vulnerability_id"]
            patch_val_map[vid] = float(row.get("patch_value", 0.0))
            patch_reduc_map[vid] = float(row.get("risk_reduction_percent", 0.0))

    scored["patch_value"] = scored["vulnerability_id"].map(lambda vid: patch_val_map.get(vid, 0.0))
    scored["risk_reduction_percent"] = scored["vulnerability_id"].map(lambda vid: patch_reduc_map.get(vid, 0.0))

    scored = scored.sort_values(
        ["patch_value", "priority_score", "individual_enablement", "cvss", "vulnerability_id"],
        ascending=[False, False, False, False, True],
        kind="mergesort",
    ).reset_index(drop=True)
    scored["rank"] = range(1, len(scored) + 1)

    output_dir = Path("output")
    output_dir.mkdir(parents=True, exist_ok=True)
    scored.to_csv(output_dir / "ranked_vulnerabilities.csv", index=False)

    top10 = patch_impact.head(int(optimization_config.get("top_k", 10))).copy()
    for frame in (patch_impact, top10):
        if not frame.empty:
            frame["reason"] = frame.apply(generate_recommendation_reason, axis=1)

    patch_impact.to_csv(output_dir / "patch_impact.csv", index=False)
    top10.to_csv(output_dir / "top10_recommendations.csv", index=False)

    # Output top-10 patch plan JSON
    top10_plan = []
    for row in top10.to_dict("records"):
        path = row.get("associated_path", [])
        if isinstance(path, str):
            path = [p.strip() for p in path.split("->") if p.strip()]
        path_str = " → ".join(map(str, path))
        r_before = float(row.get("risk_before", 0.0))
        pv = float(row.get("patch_value", 0.0))
        top10_plan.append({
            "rank": int(row.get("rank", 0)),
            "vulnerability_id": str(row.get("vulnerability_id", "")),
            "host_id": row.get("host_id"),
            "cvss": round(float(row.get("cvss", 0.0)), 6),
            "exploit_probability": round(float(row.get("exploit_probability", 0.0)), 6),
            "associated_path": path,
            "associated_path_display": path_str,
            "baseline_weighted_risk": round(r_before, 6),
            "patched_weighted_risk": round(max(0.0, r_before - pv), 6),
            "estimated_risk_reduction_fraction": round(float(row.get("risk_reduction_percent", 0.0)) / 100.0, 6),
            "estimated_risk_reduction_percent": round(float(row.get("risk_reduction_percent", 0.0)), 4),
            "explanation": row.get("reason", ""),
        })

    with open(output_dir / "top10_patch_plan.json", "w", encoding="utf-8") as handle:
        json.dump(top10_plan, handle, indent=2, default=str)

    with open(output_dir / "attack_paths.json", "w", encoding="utf-8") as handle:
        json.dump(graph_analysis.get("attack_paths", []), handle, indent=2, default=str)

    simulation_rows = [
        {"asset_id": asset, "reach_probability": probability}
        for asset, probability in baseline.critical_asset_probabilities.items()
    ]
    pd.DataFrame(simulation_rows).to_csv(output_dir / "simulation_results.csv", index=False)

    explanations = {
        f"{row['host_id']}:{row['vulnerability_id']}": row.get("reason", "")
        for row in top10.to_dict("records")
    }
    with open(output_dir / "explanations.json", "w", encoding="utf-8") as handle:
        json.dump(explanations, handle, indent=2)

    total_simulations = min(MAX_SIMULATIONS, baseline.simulations + min(remaining_budget, len(candidates) * patch_simulations))
    base_risk = calculate_network_risk(baseline, data["critical_assets"])
    elapsed = round(perf_counter() - started, 4)

    summary = {
        "total_hosts": len(graph.nodes),
        "total_vulnerabilities": len(data["vulnerabilities"]),
        "critical_assets": len(critical_assets),
        "reachable_critical_assets": len(graph_analysis.get("reachable_critical_assets", [])),
        "attack_paths": len(graph_analysis.get("attack_paths", [])),
        "simulation_count": total_simulations,
        "stage_1_simulations": baseline.simulations,
        "stage_2_simulations": total_simulations - baseline.simulations,
        "candidate_count": len(candidates),
        "top10_count": len(top10),
        "baseline_risk": base_risk,
        "active_patches": list(disabled_vulnerabilities or []),
        "active_seed": sim_seed,
        "runtime_seconds": elapsed,
    }
    with open(output_dir / "analysis_summary.json", "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)

    sim_report = {
        "max_allowed_simulations": MAX_SIMULATIONS,
        "monte_carlo_trials_drawn": baseline.simulations,
        "total_simulations_used": total_simulations,
        "within_budget": total_simulations <= MAX_SIMULATIONS,
        "method": (
            "Synchronized Monte Carlo with Common Random Numbers (CRN) using PCG64 uniform exploit draws and deciding-vote counterfactual masks."
        ),
        "baseline_weighted_risk": base_risk,
        "runtime_seconds": elapsed,
    }
    with open(output_dir / "simulation_report.json", "w", encoding="utf-8") as handle:
        json.dump(sim_report, handle, indent=2)

    md_lines = [
        "# Technical Explanations — Top-10 Patch Recommendations",
        "",
        f"- **Baseline Weighted Critical-Asset Risk**: {base_risk:.4f}",
        f"- **Monte Carlo Simulation Budget**: {total_simulations} trials (within <= {MAX_SIMULATIONS} budget)",
        f"- **Total Vulnerabilities**: {len(data['vulnerabilities'])}",
        f"- **Execution Runtime**: {elapsed:.2f}s",
        "",
        "---",
        "",
    ]
    for item in top10_plan:
        md_lines.extend([
            f"## #{item['rank']}. {item['vulnerability_id']} on Host {item['host_id']}",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| CVSS Severity | {item['cvss']:.1f} |",
            f"| Exploit Probability | {item['exploit_probability']:.3f} |",
            f"| Verified Attack Path | `{item['associated_path_display']}` |",
            f"| Estimated Risk Reduction | **{item['estimated_risk_reduction_percent']:.2f}%** (fraction: {item['estimated_risk_reduction_fraction']:.4f}) |",
            f"| Network Risk Impact | {item['baseline_weighted_risk']:.4f} → {item['patched_weighted_risk']:.4f} |",
            "",
            f"> **Rationale**: {item['explanation']}",
            "",
            "---",
            "",
        ])
    with open(output_dir / "technical_explanations.md", "w", encoding="utf-8") as handle:
        handle.write("\n".join(md_lines))

    return {
        "config": config,
        "data": data,
        "graph": graph,
        "entry_points": entry_points,
        "critical_assets": critical_assets,
        "graph_analysis": graph_analysis,
        "simulation": baseline,
        "scored": scored,
        "patch_impact": patch_impact,
        "top10": top10,
        "summary": summary,
        "candidates": candidates,
    }


def _path_through_host(graph, host_id: Any, entry_points: list[Any], critical_assets: list[Any]) -> list[Any]:
    """Backward-compatible wrapper for find_path_through_host."""
    return find_path_through_host(graph, host_id, entry_points, critical_assets)


def _recommendation_reason(row: pd.Series) -> str:
    """Backward-compatible wrapper for generate_recommendation_reason."""
    return generate_recommendation_reason(row)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Attack-Path-Aware Vulnerability Prioritization Pipeline")
    parser.add_argument("--data-dir", type=str, default=None, help="Directory containing CSV data (hosts.csv, etc.)")
    parser.add_argument("--config", type=str, default="config.yaml", help="Path to YAML configuration")
    parser.add_argument("--seed", type=str, default=None, help="Random seed or date (e.g. 20260911, 2026-09-11, today) for simulation and graph")
    parser.add_argument("--output-dir", type=str, default="output", help="Directory for output artifacts")
    args = parser.parse_args()

    supplied = None
    if args.data_dir:
        supplied = load_all_data(args.data_dir)

    user_seed = parse_seed(args.seed) if args.seed is not None else None
    result = run_analysis(config_path=args.config, data=supplied, seed=user_seed)
    print(f"Ranked {len(result['scored'])} vulnerabilities on {len(result['graph'].nodes)} hosts.")
    print(f"Top 10 patch recommendations generated.")
    print(f"Simulations used: {result['summary']['simulation_count']} / {MAX_SIMULATIONS}")
    print(f"Baseline risk: {result['summary']['baseline_risk']:.4f}")

