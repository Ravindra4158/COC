import logging

from fastapi import APIRouter, HTTPException

from app.schemas import NetworkResponse
from app.serialization import _clean
from app.state import get_analysis

logger = logging.getLogger(__name__)
router = APIRouter(tags=["network"])


@router.get("/network", response_model=NetworkResponse)
def get_network():
    try:
        result = get_analysis()
        graph = result["graph"]
        nodes = []
        for node, attrs in graph.nodes(data=True):
            criticality = attrs.get("criticality", 0.0)
            nodes.append({
                "id": str(node),
                "label": str(attrs.get("name", node)),
                "is_critical": bool(attrs.get("is_critical", False)),
                "criticality": float(criticality) if criticality is not None else 0.0,
                "vulnerability_count": len(attrs.get("vulnerabilities", [])),
                "is_entry_point": node in result["entry_points"] or bool(attrs.get("is_entry_point", False)),
                "vulnerabilities": [str(value) for value in attrs.get("vulnerabilities", [])],
            })
        edges = [{"source": str(source), "target": str(target)} for source, target in graph.edges]
        attack_paths = result["graph_analysis"].get("shortest_paths", [])
        return _clean({"nodes": nodes, "edges": edges, "attack_paths": attack_paths})
    except Exception as exc:
        logger.exception("Network request failed")
        raise HTTPException(status_code=500, detail="Network data is unavailable") from exc
