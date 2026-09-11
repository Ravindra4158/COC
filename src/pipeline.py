"""Cached Phase 1-5 analysis orchestration for the API and dashboard."""

from pathlib import Path
from time import perf_counter
import json
from collections.abc import Mapping
from typing import Any

import networkx as nx
import pandas as pd
import yaml

from src.data.loader import generate_development_instance, load_all_data
from src.data.validator import validate_all
from src.graph.analysis import analyze_attack_graph
from src.graph.builder import build_network_graph
from src.optimization.patch_impact import evaluate_all_patch_impacts
from src.optimization.candidate_filter import filter_patch_candidates
from src.simulation.budget import MAX_SIMULATIONS
from src.simulation.monte_carlo import run_baseline_simulation
from src.scoring.priority_score import score_all_vulnerabilities


def run_analysis(
    config_path: str | Path = "config.yaml",
    data: Mapping[str, pd.DataFrame] | None = None,
    disabled_vulnerabilities: list[str] | None = None,
    seed: int | None = None,
) -> dict[str, Any]:
    """Run one analysis over supplied evaluator data or the local dev instance.

    ``data`` takes precedence over local generation. This lets an evaluator provide
    an unseen network and finding set without changing the ranking implementation.
    ``disabled_vulnerabilities`` allows simulating the network state after patches are applied.
    ``seed`` allows testing alternative reproducible states/topologies.
    """
    started = perf_counter()
    with open(config_path, encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}
    development_config = config.get("development_instance", {})
    if seed is not None:
        development_config = dict(development_config)
        development_config["seed"] = seed

    supplied_data = data is not None
    if supplied_data:
        data = dict(data)
    elif development_config.get("enabled", False):
        data = generate_development_instance(development_config)
    else:
        raw_dir = config["data"]["raw_dir"]
        data = load_all_data(raw_dir)

    if disabled_vulnerabilities:
        disabled_set = set(disabled_vulnerabilities)
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
    entry_points = list(configured_entries) or [node for node, attrs in graph.nodes(data=True) if attrs.get("is_entry_point")]
    critical_assets = list(data["critical_assets"]["host_id"])
    # A shortest witness per entry/asset is sufficient for explanation and avoids
    # enumerating the exponential set of simple paths in the undirected graph.
    graph_analysis = analyze_attack_graph(
        graph, entry_points, critical_assets, max_path_length=39, max_paths_per_target=1
    )
    simulation_config = config.get("simulation", {})
    sim_seed = seed if seed is not None else int(simulation_config.get("seed", 42))
    baseline = run_baseline_simulation(
        graph,
        data["vulnerabilities"],
        entry_points,
        critical_assets,
        # Reserve half of the hard budget for individual patch evaluations.
        n_simulations=min(int(simulation_config.get("default_simulations", 2000)), MAX_SIMULATIONS // 2),
        seed=sim_seed,
        max_steps=int(simulation_config.get("max_attack_steps", 50)),
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
    # The final-evaluation format requires a valid witness path for each chosen
    # patch. Store one per host before any candidate is selected.
    scored["associated_path"] = scored["host_id"].map(
        lambda host_id: _path_through_host(graph, host_id, entry_points, critical_assets)
    )
    output_dir = Path("output")
    output_dir.mkdir(parents=True, exist_ok=True)
    scored.to_csv(output_dir / "ranked_vulnerabilities.csv", index=False)
    optimization_config = config.get("optimization", {})
    candidates = [
        candidate for candidate in filter_patch_candidates(scored, graph_analysis)
        if candidate.get("associated_path")
    ]
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
    top10 = patch_impact.head(int(optimization_config.get("top_k", 10))).copy()
    for frame in (patch_impact, top10):
        if not frame.empty:
            frame["reason"] = frame.apply(_recommendation_reason, axis=1)
    patch_impact.to_csv(output_dir / "patch_impact.csv", index=False)
    top10.to_csv(output_dir / "top10_recommendations.csv", index=False)
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
    total_simulations = baseline.simulations + len(candidates) * patch_simulations
    summary = {
        "total_hosts": len(graph.nodes),
        "total_vulnerabilities": len(data["vulnerabilities"]),
        "critical_assets": len(critical_assets),
        "reachable_critical_assets": len(graph_analysis.get("reachable_critical_assets", [])),
        "attack_paths": len(graph_analysis.get("attack_paths", [])),
        "simulation_count": total_simulations,
        "stage_1_simulations": baseline.simulations,
        "stage_2_simulations": len(candidates) * patch_simulations,
        "candidate_count": len(candidates),
        "top10_count": len(top10),
        "baseline_risk": float(sum(
            baseline.critical_asset_probabilities.get(asset, 0.0)
            * float(row.get("criticality", row.get("impact_weight", 1.0)))
            for asset, row in zip(critical_assets, data["critical_assets"].to_dict("records"))
        )),
        "active_patches": list(disabled_vulnerabilities or []),
        "active_seed": sim_seed,
        "runtime_seconds": round(perf_counter() - started, 4),
    }
    with open(output_dir / "analysis_summary.json", "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)
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


def _recommendation_reason(row: pd.Series) -> str:
    assets = row.get("critical_assets_affected", [])
    if not isinstance(assets, list):
        assets = [assets] if assets else []
    asset_text = ", ".join(str(asset) for asset in assets) or "downstream critical assets"
    return (
        f"{row['vulnerability_id']} on {row['host_id']} affects {int(row.get('attack_path_count', 0))} "
        f"attack-path occurrence(s) toward {asset_text}; virtual patching reduces risk by "
        f"{float(row.get('risk_reduction_percent', 0.0)):.1f}% via path "
        f"{' -> '.join(map(str, row.get('associated_path', [])))}."
    )


def _path_through_host(graph, host_id: Any, entry_points: list[Any], critical_assets: list[Any]) -> list[Any]:
    """Construct a simple entry-to-critical path that includes ``host_id``.

    Removing the pre-host segment before finding the continuation guarantees that
    reported paths do not repeat nodes. Empty means no valid witness exists.
    """
    for entry_point in entry_points:
        for critical_asset in critical_assets:
            try:
                entry_to_host = nx.shortest_path(graph, entry_point, host_id)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
            available = graph.copy()
            available.remove_nodes_from(entry_to_host[:-1])
            if critical_asset not in available:
                continue
            try:
                continuation = nx.shortest_path(available, host_id, critical_asset)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
            return entry_to_host + continuation[1:]
    return []
