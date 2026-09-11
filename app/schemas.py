from typing import Any

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str


class AnalysisSummary(BaseModel):
    status: str
    total_hosts: int
    total_vulnerabilities: int
    critical_assets: int
    reachable_critical_assets: int
    critical_asset_reach_probability: float
    baseline_risk: float
    simulations: int
    total_simulations: int = 0
    candidate_count: int = 0
    attack_paths: int = 0
    active_patches: list[str] = Field(default_factory=list)
    active_seed: int | None = None
    updated_at: str | None = None


class NetworkNode(BaseModel):
    id: str
    label: str
    is_critical: bool
    criticality: float = 0.0
    vulnerability_count: int
    is_entry_point: bool = False
    vulnerabilities: list[str] = Field(default_factory=list)


class NetworkEdge(BaseModel):
    source: str
    target: str


class NetworkResponse(BaseModel):
    nodes: list[NetworkNode]
    edges: list[NetworkEdge]
    attack_paths: list[dict[str, Any]] = Field(default_factory=list)


class VulnerabilityResult(BaseModel):
    rank: int
    host_id: str
    vulnerability_id: str
    cvss: float
    exploit_probability: float
    attacker_reachability: float
    critical_asset_exposure: float
    priority_score: float
    patch_value: float = 0.0
    risk_before: float = 0.0
    risk_after: float = 0.0
    risk_reduction_percent: float = 0.0
    path_frequency: int = 0
    reachable_critical_asset_count: int = 0
    reason: str | None = None


class ItemsResponse(BaseModel):
    items: list[dict[str, Any]]


class RunAnalysisRequest(BaseModel):
    disabled_vulnerabilities: list[str] = Field(default_factory=list)
    seed: int | None = None


class RefreshResponse(BaseModel):
    status: str
    message: str
    active_patches: list[str] = Field(default_factory=list)
    active_seed: int | None = None
