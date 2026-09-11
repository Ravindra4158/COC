import pytest
from fastapi.testclient import TestClient

from app.main import app
from src.pipeline import run_analysis

client = TestClient(app)


def test_disabled_vulnerability_reduces_risk_and_reranks():
    baseline = run_analysis()
    base_risk = baseline["summary"]["baseline_risk"]
    top_v = baseline["top10"].iloc[0]["vulnerability_id"]

    # Patch the #1 vulnerability
    patched = run_analysis(disabled_vulnerabilities=[top_v])
    patched_risk = patched["summary"]["baseline_risk"]

    assert patched_risk < base_risk, f"Patching {top_v} should reduce risk (was {base_risk}, now {patched_risk})"
    # The patched vulnerability should no longer be in the top recommendations
    new_top_vids = list(patched["top10"]["vulnerability_id"])
    assert top_v not in new_top_vids, f"{top_v} was patched and should not be recommended"
    assert len(patched["top10"]) == 10


def test_alternative_seed_changes_topology_and_ranking():
    res_default = run_analysis(seed=20260911)
    res_alt = run_analysis(seed=42)

    top_default = list(res_default["top10"]["vulnerability_id"])
    top_alt = list(res_alt["top10"]["vulnerability_id"])

    assert top_default != top_alt, "Different random seeds should yield different topology and top-10 rankings"
    assert len(top_alt) == 10


def test_api_patch_and_reset_state():
    # Initial state
    resp = client.get("/analysis")
    assert resp.status_code == 200
    init_risk = resp.json()["baseline_risk"]

    # Apply patch via API
    patch_resp = client.post("/analysis/run", json={"disabled_vulnerabilities": ["h39-v2"]})
    assert patch_resp.status_code == 200
    data = patch_resp.json()
    assert "h39-v2" in data["active_patches"]

    # Check updated risk
    updated_resp = client.get("/analysis")
    assert updated_resp.status_code == 200
    new_risk = updated_resp.json()["baseline_risk"]
    assert new_risk < init_risk

    # Reset state via API
    reset_resp = client.post("/analysis/reset")
    assert reset_resp.status_code == 200
    assert reset_resp.json()["active_patches"] == []

    # Verify risk returned to baseline
    restored_resp = client.get("/analysis")
    assert restored_resp.json()["baseline_risk"] == pytest.approx(init_risk, rel=1e-4)
