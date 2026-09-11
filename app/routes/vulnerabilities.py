import logging

from fastapi import APIRouter, HTTPException

from app.serialization import frame_records
from app.state import get_analysis

logger = logging.getLogger(__name__)
router = APIRouter(tags=["vulnerabilities"])


@router.get("/vulnerabilities")
def get_vulnerabilities():
    try:
        result = get_analysis()
        scored = result["scored"]
        patches = result["patch_impact"]
        patch_columns = ["host_id", "vulnerability_id", "patch_value", "risk_before", "risk_after", "risk_reduction_percent", "associated_path", "reason"]
        patch_records = patches[patch_columns].to_dict("records") if not patches.empty else []
        patch_map = {(str(row["host_id"]), str(row["vulnerability_id"])): row for row in patch_records}
        rows = []
        for row in frame_records(scored):
            patch = patch_map.get((str(row["host_id"]), str(row["vulnerability_id"])), {})
            row.update({key: patch.get(key, 0.0) for key in patch_columns[2:]})
            rows.append(row)
        return {"items": rows}
    except Exception as exc:
        logger.exception("Vulnerability request failed")
        raise HTTPException(status_code=500, detail="Vulnerability data is unavailable") from exc
