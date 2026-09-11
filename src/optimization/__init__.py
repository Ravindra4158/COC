"""Phase 5 virtual patching and patch-impact optimization."""

from .candidate_filter import filter_patch_candidates
from .patch_impact import calculate_network_risk, evaluate_all_patch_impacts, evaluate_patch_impact, virtually_patch
from .ranking import get_top_10_recommendations, rank_patch_candidates

__all__ = [
    "calculate_network_risk",
    "evaluate_all_patch_impacts",
    "evaluate_patch_impact",
    "filter_patch_candidates",
    "get_top_10_recommendations",
    "rank_patch_candidates",
    "virtually_patch",
]
