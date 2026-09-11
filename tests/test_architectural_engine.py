"""Verification tests for the refactored, attack-path-aware vulnerability prioritization engine."""

from pathlib import Path
import networkx as nx
import numpy as np
import pytest

from src.data.loader import generate_development_instance
from src.explanation.explainer import generate_recommendation_reason
from src.graph.builder import build_network_graph
from src.graph.paths import find_path_through_host
from src.pipeline import run_analysis
from src.scoring.priority_score import score_all_vulnerabilities
from src.simulation.monte_carlo import evaluate_synchronized_monte_carlo


def test_erdos_renyi_graph_connectivity_and_stitching():
    """Graph with n=40, p=0.09 on seed 20260911 must be connected after sequential stitching."""
    config = {
        "topology": {"node_count": 40, "edge_probability": 0.09, "directed": False},
        "vulnerabilities": {
            "per_host": 2,
            "cvss_min": 3.0,
            "cvss_max": 9.8,
            "exploit_probability": {"min": 0.05, "max": 0.95, "offset": 2.0, "divisor": 8.0},
        },
        "seed": 20260911,
        "entry_points": [0, 1],
        "critical_asset_weights": {35: 1.0, 36: 2.0, 37: 3.0, 38: 4.0, 39: 5.0},
    }
    data = generate_development_instance(config)
    graph = build_network_graph(data["hosts"], data["network_edges"], directed=False)
    assert nx.is_connected(graph), "Erdos-Renyi graph must be fully connected"
    assert len(graph.nodes) == 40
    assert len(data["vulnerabilities"]) == 80  # 2 per host


def test_cvss_and_bounded_exploit_probability():
    """Vulnerabilities must have CVSS in [3.0, 9.8] and exploit prob in [0.05, 0.95]."""
    config = {
        "topology": {"node_count": 40, "edge_probability": 0.09, "directed": False},
        "vulnerabilities": {
            "per_host": 2,
            "cvss_min": 3.0,
            "cvss_max": 9.8,
            "exploit_probability": {"min": 0.05, "max": 0.95, "offset": 2.0, "divisor": 8.0},
        },
        "seed": 20260911,
        "entry_points": [0, 1],
        "critical_asset_weights": {35: 1.0, 36: 2.0, 37: 3.0, 38: 4.0, 39: 5.0},
    }
    data = generate_development_instance(config)
    vulns = data["vulnerabilities"]
    assert (vulns["cvss"] >= 3.0).all() and (vulns["cvss"] <= 9.8).all()
    assert (vulns["exploit_probability"] >= 0.05).all() and (vulns["exploit_probability"] <= 0.95).all()


def test_sibling_enablement_calculation():
    """Marginal enablement ΔP_comp must properly account for sibling vulnerability dilution."""
    graph = nx.Graph([(0, 1), (1, 35)])
    graph.nodes[1]["vulnerabilities"] = ["v1", "v2"]
    vulns = [
        {"vuln_id": "v1", "host_id": 1, "cvss": 9.0, "exploit_probability": 0.8},
        {"vuln_id": "v2", "host_id": 1, "cvss": 7.0, "exploit_probability": 0.5},
    ]
    scored = score_all_vulnerabilities(graph, vulns, [0, 1, 35], [0], {35: 1.0}, output_path=None)
    v1_row = scored.loc[scored["vulnerability_id"] == "v1"].iloc[0]
    v2_row = scored.loc[scored["vulnerability_id"] == "v2"].iloc[0]

    # ΔP_comp(v1) = p1 * (1 - p2) = 0.8 * (1 - 0.5) = 0.4
    # ΔP_comp(v2) = p2 * (1 - p1) = 0.5 * (1 - 0.8) = 0.1
    assert v1_row["individual_enablement"] == pytest.approx(0.40, rel=1e-3)
    assert v2_row["individual_enablement"] == pytest.approx(0.10, rel=1e-3)


def test_synchronized_monte_carlo_budget_and_variance():
    """Synchronized Monte Carlo must respect simulation budget and deliver zero-variance patch evaluations."""
    config = {
        "topology": {"node_count": 40, "edge_probability": 0.09, "directed": False},
        "vulnerabilities": {
            "per_host": 2,
            "cvss_min": 3.0,
            "cvss_max": 9.8,
            "exploit_probability": {"min": 0.05, "max": 0.95, "offset": 2.0, "divisor": 8.0},
        },
        "seed": 20260911,
        "entry_points": [0, 1],
        "critical_asset_weights": {35: 1.0, 36: 2.0, 37: 3.0, 38: 4.0, 39: 5.0},
    }
    data = generate_development_instance(config)
    graph = build_network_graph(data["hosts"], data["network_edges"], directed=False)
    entry_points = [0, 1]
    critical_assets = {35: 1.0, 36: 2.0, 37: 3.0, 38: 4.0, 39: 5.0}

    res = evaluate_synchronized_monte_carlo(
        graph=graph,
        vulnerabilities=data["vulnerabilities"],
        entry_points=entry_points,
        critical_assets=critical_assets,
        n_sims=4000,
        seed=20260911,
    )

    assert res.total_simulations == 4000
    assert res.baseline_risk > 0.0
    assert len(res.patch_values) == 80
    assert any(pv > 0.0 for pv in res.patch_values.values())


def test_end_to_end_pipeline_top10_quality_and_path_witnesses():
    """Full pipeline must produce Top 10 recommendations with strictly positive risk reduction and valid attack paths."""
    result = run_analysis()
    top10 = result["top10"]
    assert len(top10) == 10, "Should recommend exactly 10 vulnerabilities"

    summary = result["summary"]
    assert summary["simulation_count"] <= 4000, f"Must stay within 4000 budget, got {summary['simulation_count']}"
    assert summary["baseline_risk"] > 0.0

    entry_points = set(result["entry_points"])
    critical_assets = set(result["critical_assets"])

    for _, row in top10.iterrows():
        # Positive risk reduction
        assert row["patch_value"] > 0.0, f"Recommendation {row['vulnerability_id']} has non-positive patch value"
        assert row["risk_reduction_percent"] > 0.0

        # Valid attack path witness
        path = row["associated_path"]
        assert len(path) >= 2, f"Path for {row['vulnerability_id']} must have at least 2 nodes, got {path}"
        assert path[0] in entry_points, f"Path must start at an entry point, got {path[0]}"
        assert path[-1] in critical_assets, f"Path must terminate at a critical asset, got {path[-1]}"
        assert row["host_id"] in path, f"Host {row['host_id']} must lie on path {path}"

        # Explainability reason
        reason = generate_recommendation_reason(row)
        assert str(row["vulnerability_id"]) in reason
        assert str(row["host_id"]) in reason


def test_generated_output_artifacts_exist():
    """Ensure all required competition and API output artifacts are generated."""
    run_analysis()
    output_dir = Path("output")
    assert (output_dir / "ranked_vulnerabilities.csv").is_file()
    assert (output_dir / "patch_impact.csv").is_file()
    assert (output_dir / "top10_recommendations.csv").is_file()
    assert (output_dir / "analysis_summary.json").is_file()
    assert (output_dir / "explanations.json").is_file()
