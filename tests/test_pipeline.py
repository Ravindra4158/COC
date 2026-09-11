from src.pipeline import run_analysis


def test_complete_pipeline_produces_phase_five_results():
    result = run_analysis()
    assert len(result["graph"].nodes) == 40
    assert not result["graph"].is_directed()
    assert len(result["data"]["vulnerabilities"]) == 80
    assert result["simulation"].simulations == 2000
    assert not result["scored"].empty
    assert not result["patch_impact"].empty
    assert len(result["top10"]) == 10
    assert result["summary"]["simulation_count"] <= 4000
    assert result["top10"]["associated_path"].map(bool).all()
    assert result["patch_impact"].iloc[0]["patch_value"] >= 0
