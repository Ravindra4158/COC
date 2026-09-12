"""Tests for generalized evaluation on arbitrary CSV datasets."""

import json
from pathlib import Path
import pandas as pd
import pytest

import sys

from src.data.loader import load_all_data
from src.pipeline import run_analysis

submission_dir = Path(__file__).resolve().parent.parent / "graphify-challenge-submission"
if str(submission_dir) not in sys.path:
    sys.path.insert(0, str(submission_dir))

from rank_vulnerabilities import run_prioritization


def test_general_csv_evaluation_with_string_nodes_and_missing_probs(tmp_path):
    """Ensure the prioritization engine handles arbitrary CSV schemas on test day."""
    hosts_df = pd.DataFrame([
        {"host_id": "gw1", "name": "Gateway 1", "is_entry_point": True},
        {"host_id": "gw2", "name": "Gateway 2", "is_entry_point": False},
        {"host_id": "srv1", "name": "Server 1", "is_entry_point": False},
        {"host_id": "srv2", "name": "Server 2", "is_entry_point": False},
        {"host_id": "db_master", "name": "Database Master", "is_entry_point": False},
        {"host_id": "vault", "name": "Secret Vault", "is_entry_point": False},
    ])
    # Deliberately disconnected components: {gw1, srv1, db_master} and {gw2, srv2, vault}
    edges_df = pd.DataFrame([
        {"source": "gw1", "target": "srv1"},
        {"source": "srv1", "target": "db_master"},
        {"source": "gw2", "target": "srv2"},
        {"source": "srv2", "target": "vault"},
    ])
    # Deliberately omit exploit_probability to test automatic CVSS derivation
    vulns_df = pd.DataFrame([
        {"vuln_id": "V-GW1", "host_id": "gw1", "cvss": 7.0},
        {"vuln_id": "V-SRV1", "host_id": "srv1", "cvss": 9.5},
        {"vuln_id": "V-DB", "host_id": "db_master", "cvss": 8.0},
        {"vuln_id": "V-GW2", "host_id": "gw2", "cvss": 6.5},
        {"vuln_id": "V-SRV2", "host_id": "srv2", "cvss": 8.8},
        {"vuln_id": "V-VAULT", "host_id": "vault", "cvss": 9.2},
    ])
    critical_df = pd.DataFrame([
        {"host_id": "db_master", "criticality": 4.5},
        {"host_id": "vault", "criticality": 5.0},
    ])

    hosts_path = tmp_path / "hosts.csv"
    edges_path = tmp_path / "network_edges.csv"
    vulns_path = tmp_path / "vulnerabilities.csv"
    crit_path = tmp_path / "critical_assets.csv"

    hosts_df.to_csv(hosts_path, index=False)
    edges_df.to_csv(edges_path, index=False)
    vulns_df.to_csv(vulns_path, index=False)
    critical_df.to_csv(crit_path, index=False)

    out_dir = tmp_path / "output"

    # Test standalone runner
    res = run_prioritization(
        data_dir=tmp_path,
        output_dir=out_dir,
        n_sims=2000,
    )

    assert res["baseline_risk"] > 0.0
    assert len(res["rows"]) == 6
    assert (out_dir / "ranked_vulnerabilities.csv").is_file()
    assert (out_dir / "top10_patch_plan.json").is_file()
    assert (out_dir / "simulation_report.json").is_file()
    assert (out_dir / "technical_explanations.md").is_file()

    with (out_dir / "top10_patch_plan.json").open("r", encoding="utf-8") as f:
        plan = json.load(f)

    assert len(plan) > 0
    top = plan[0]
    assert "vulnerability_id" in top
    assert "associated_path" in top
    assert len(top["associated_path"]) >= 2
    assert top["associated_path"][0] == "gw1"
    assert top["estimated_risk_reduction_percent"] >= 0.0
    assert "explanation" in top and len(top["explanation"]) > 10

    # Test pipeline runner
    data = load_all_data(tmp_path)
    pipe_res = run_analysis(data=data)
    assert pipe_res["summary"]["baseline_risk"] > 0.0
    assert not pipe_res["top10"].empty
