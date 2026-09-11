import logging

from fastapi import APIRouter, HTTPException

from app.schemas import AnalysisSummary, RefreshResponse, RunAnalysisRequest
from app.serialization import _clean
from app.state import cache_timestamp, get_active_patches, get_active_seed, get_analysis, reset_state
from src.optimization.patch_impact import calculate_network_risk

logger = logging.getLogger(__name__)
router = APIRouter(tags=["analysis"])


def summary(result) -> dict:
    simulation = result["simulation"]
    return _clean({
        "status": "complete",
        "total_hosts": len(result["graph"].nodes),
        "total_vulnerabilities": len(result["data"]["vulnerabilities"]),
        "critical_assets": len(result["critical_assets"]),
        "reachable_critical_assets": len(result["graph_analysis"]["reachable_critical_assets"]),
        "critical_asset_reach_probability": simulation.critical_asset_reach_probability,
        "baseline_risk": calculate_network_risk(simulation, result["data"]["critical_assets"]),
        "simulations": simulation.simulations,
        "total_simulations": result.get("summary", {}).get("simulation_count", simulation.simulations),
        "candidate_count": result.get("summary", {}).get("candidate_count", len(result.get("candidates", []))),
        "attack_paths": result.get("summary", {}).get("attack_paths", len(result["graph_analysis"].get("attack_paths", []))),
        "active_patches": get_active_patches(),
        "active_seed": get_active_seed(),
        "updated_at": cache_timestamp(),
    })


@router.get("/analysis", response_model=AnalysisSummary)
def get_analysis_summary():
    try:
        return summary(get_analysis())
    except Exception as exc:
        logger.exception("Analysis request failed")
        raise HTTPException(status_code=500, detail="Analysis is unavailable") from exc


@router.post("/analysis/run", response_model=RefreshResponse)
def refresh_analysis(request: RunAnalysisRequest | None = None):
    try:
        disabled = request.disabled_vulnerabilities if request else None
        seed = request.seed if request else None
        res = get_analysis(force=True, disabled_vulnerabilities=disabled, seed=seed)
        summary(res)
        return {
            "status": "complete",
            "message": "Analysis completed successfully",
            "active_patches": get_active_patches(),
            "active_seed": get_active_seed(),
        }
    except Exception as exc:
        logger.exception("Analysis refresh failed")
        raise HTTPException(status_code=500, detail="Analysis could not be completed") from exc


@router.post("/analysis/reset", response_model=RefreshResponse)
def reset_analysis():
    try:
        reset_state()
        res = get_analysis(force=True)
        summary(res)
        return {
            "status": "complete",
            "message": "State reset to defaults",
            "active_patches": [],
            "active_seed": None,
        }
    except Exception as exc:
        logger.exception("Analysis reset failed")
        raise HTTPException(status_code=500, detail="Reset could not be completed") from exc
