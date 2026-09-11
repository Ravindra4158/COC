import logging

from fastapi import APIRouter, HTTPException

from app.serialization import frame_records
from app.state import get_analysis

logger = logging.getLogger(__name__)
router = APIRouter(tags=["recommendations"])


@router.get("/recommendations")
def get_recommendations():
    try:
        return {"items": frame_records(get_analysis()["top10"])}
    except Exception as exc:
        logger.exception("Recommendation request failed")
        raise HTTPException(status_code=500, detail="Recommendations are unavailable") from exc
