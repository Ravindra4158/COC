"""Comprehensive verification of universal robustness across arbitrary seeds, dates, topologies, schemas, and finding counts."""

import json
from pathlib import Path
from datetime import datetime
import pandas as pd
import pytest
from fastapi.testclient import TestClient

from app.main import app
from src.data.loader import parse_seed, load_all_data
from src.pipeline import run_analysis

import sys
submission_dir = Path(__file__).resolve().parent.parent / "graphify-challenge-submission"
if str(submission_dir) not in sys.path:
    sys.path.insert(0, str(submission_dir))

from rank_vulnerabilities import run_prioritization


client = TestClient(app)


def test_parse_seed_universal_formats():
    """Verify parse_seed handles integers, date strings, keywords, and hashes seamlessly."""
    assert parse_seed(20260911) == 20260911
    assert parse_seed("20260911") == 20260911
    assert parse_seed("2026-09-11") == 20260911
    assert parse_seed("2026/09/11") == 20260911
    assert parse_seed("2026.09.11") == 20260911
    assert parse_seed("11-09-2026") == 20260911

    # Today / now keyword
    today_int = int(datetime.now().strftime("%Y%m%d"))
    assert parse_seed("today") == today_int
    assert parse_seed("TODAY") == today_int
    assert parse_seed("now") == today_int

    # Numeric strings & integers
    assert parse_seed(42) == 42
    assert parse_seed("42") == 42
    assert parse_seed("1337") == 1337

    # Arbitrary strings (deterministic positive hash)
    h1 = parse_seed("evaluation-instance-A")
    h2 = parse_seed("evaluation-instance-A")
    assert isinstance(h1, int) and h1 > 0
    assert h1 == h2

    # None and empty string
    assert parse_seed(None, default=20260911) == 20260911
    assert parse_seed("", default=20260911) == 20260911


def test_few_vulnerabilities_smaller_than_top10(tmp_path):
    """Ensure that datasets with fewer than 10 findings (e.g. 3 findings) do not crash or pad invalid rows."""
    hosts_df = pd.DataFrame([
        {"host_id": "h1", "name": "Host 1", "is_entry_point": True},
        {"host_id": "h2", "name": "Host 2", "is_entry_point": False},
        {"host_id": "h3", "name": "Host 3", "is_entry_point": False},
    ])
    edges_df = pd.DataFrame([
        {"source": "h1", "target": "h2"},
        {"source": "h2", "target": "h3"},
    ])
    vulns_df = pd.DataFrame([
        {"vuln_id": "v1", "host_id": "h1", "cvss": 7.5, "exploit_probability": 0.8},
        {"vuln_id": "v2", "host_id": "h2", "cvss": 8.0, "exploit_probability": 0.7},
        {"vuln_id": "v3", "host_id": "h3", "cvss": 9.0, "exploit_probability": 0.9},
    ])
    critical_df = pd.DataFrame([
        {"host_id": "h3", "criticality": 2.5},
    ])

    for name, df in [("hosts", hosts_df), ("network_edges", edges_df), ("vulnerabilities", vulns_df), ("critical_assets", critical_df)]:
        df.to_csv(tmp_path / f"{name}.csv", index=False)

    out_dir = tmp_path / "out"
    res = run_prioritization(data_dir=tmp_path, output_dir=out_dir, top_k=10, seed="today")
    assert len(res["top10"]) == 3
    assert len(res["rows"]) == 3
    assert (out_dir / "top10_patch_plan.json").is_file()
    assert (out_dir / "technical_explanations.md").is_file()

    # Full pipeline run
    data = load_all_data(tmp_path)
    pipe_res = run_analysis(data=data, seed="2026-09-12")
    assert len(pipe_res["top10"]) == 3
    assert pipe_res["summary"]["top10_count"] == 3


def test_column_synonyms_and_type_healing(tmp_path):
    """Ensure CSVs with synonyms like 'cve', 'node_id', 'src', 'dst', 'weight' are normalized."""
    hosts_df = pd.DataFrame([
        {"node": "10", "hostname": "Gateway", "entry": "true"},
        {"node": "20", "hostname": "Database", "entry": "false"},
    ])
    edges_df = pd.DataFrame([
        {"src": "10", "dst": "20"},
    ])
    vulns_df = pd.DataFrame([
        {"cve": "CVE-2026-001", "node_id": "10", "score": 9.5},
        {"cve": "CVE-2026-002", "node_id": "20", "score": 8.5},
    ])
    critical_df = pd.DataFrame([
        {"asset_id": "20", "weight": 5.0},
    ])

    hosts_df.to_csv(tmp_path / "hosts.csv", index=False)
    edges_df.to_csv(tmp_path / "network_edges.csv", index=False)
    vulns_df.to_csv(tmp_path / "vulnerabilities.csv", index=False)
    critical_df.to_csv(tmp_path / "critical_assets.csv", index=False)

    data = load_all_data(tmp_path)
    assert "host_id" in data["hosts"].columns
    assert "vuln_id" in data["vulnerabilities"].columns
    assert "source" in data["network_edges"].columns
    assert "target" in data["network_edges"].columns
    assert "criticality" in data["critical_assets"].columns

    pipe_res = run_analysis(data=data, seed="2026-09-11")
    assert len(pipe_res["top10"]) == 2
    assert pipe_res["summary"]["baseline_risk"] > 0.0


def test_zero_critical_assets_graceful_handling(tmp_path):
    """Ensure that if critical_assets is empty, the software returns 0 risk without division by zero."""
    hosts_df = pd.DataFrame([
        {"host_id": "A", "name": "Host A", "is_entry_point": True},
        {"host_id": "B", "name": "Host B", "is_entry_point": False},
    ])
    edges_df = pd.DataFrame([{"source": "A", "target": "B"}])
    vulns_df = pd.DataFrame([{"vuln_id": "V1", "host_id": "A", "cvss": 6.0, "exploit_probability": 0.5}])
    crit_df = pd.DataFrame(columns=["host_id", "criticality"])

    hosts_df.to_csv(tmp_path / "hosts.csv", index=False)
    edges_df.to_csv(tmp_path / "network_edges.csv", index=False)
    vulns_df.to_csv(tmp_path / "vulnerabilities.csv", index=False)
    crit_df.to_csv(tmp_path / "critical_assets.csv", index=False)

    out_dir = tmp_path / "out"
    res = run_prioritization(data_dir=tmp_path, output_dir=out_dir, seed=20260911)
    assert res["baseline_risk"] == 0.0
    assert len(res["rows"]) == 1


def test_api_date_and_string_seeds():
    """Verify that FastAPI backend accepts string and date seeds in POST /analysis/run."""
    resp = client.post("/analysis/run", json={"seed": "2026-09-11"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["active_seed"] == 20260911

    resp_today = client.post("/analysis/run", json={"seed": "today"})
    assert resp_today.status_code == 200
    today_int = int(datetime.now().strftime("%Y%m%d"))
    assert resp_today.json()["active_seed"] == today_int

    # Reset
    reset_resp = client.post("/analysis/reset")
    assert reset_resp.status_code == 200
