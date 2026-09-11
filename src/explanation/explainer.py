"""Explainability generation for prioritized vulnerabilities and patch recommendations."""

from __future__ import annotations

from typing import Any
import pandas as pd


def generate_explanation_text(
    vulnerability_id: str,
    host_id: Any,
    cvss: float,
    exploit_probability: float,
    associated_path: list[Any] | None = None,
    individual_enablement: float | None = None,
    baseline_risk: float | None = None,
    patched_risk: float | None = None,
    risk_reduction_percent: float | None = None,
    critical_assets_affected: list[Any] | None = None,
    choke_point_frequency: int | None = None,
) -> str:
    """Construct a comprehensive, professional explanation for a prioritized vulnerability."""
    path_str = " → ".join(map(str, associated_path)) if associated_path else f"host {host_id}"
    reasons = [
        f"{vulnerability_id} on host {host_id} (CVSS {cvss:.1f}, exploit prob {exploit_probability:.3f}) lies on attack path {path_str}."
    ]

    if individual_enablement is not None:
        reasons.append(
            f"Marginal host-compromise enablement: {individual_enablement:.4f} (probability this vulnerability uniquely opens the host)."
        )

    if choke_point_frequency is not None and choke_point_frequency > 0:
        reasons.append(f"Acts as a bottleneck node traversing {choke_point_frequency} attack path(s).")

    if critical_assets_affected:
        assets_str = ", ".join(map(str, critical_assets_affected))
        reasons.append(f"Threatens downstream critical assets: [{assets_str}].")

    if baseline_risk is not None and patched_risk is not None and risk_reduction_percent is not None:
        reasons.append(
            f"Mitigating it reduces network weighted critical-asset risk from {baseline_risk:.4f} to {patched_risk:.4f} (-{risk_reduction_percent:.1f}%)."
        )

    return " ".join(reasons)


def generate_recommendation_reason(row: pd.Series | dict[str, Any]) -> str:
    """Generate a concise reason string for a patch recommendation row."""
    data = row.to_dict() if hasattr(row, "to_dict") else dict(row)
    vid = data.get("vulnerability_id", data.get("vuln_id", "Unknown"))
    host = data.get("host_id", "?")
    cvss = float(data.get("cvss", 0.0))
    prob = float(data.get("exploit_probability", 0.0))
    path = data.get("associated_path", [])
    if isinstance(path, str):
        path = [p.strip() for p in path.split("->") if p.strip()]

    enablement = data.get("individual_enablement", data.get("marginal_enablement"))
    if enablement is not None:
        enablement = float(enablement)

    r_before = data.get("risk_before")
    r_after = data.get("risk_after")
    r_reduc = data.get("risk_reduction_percent")
    choke_count = data.get("path_frequency", data.get("attack_path_count"))
    assets = data.get("critical_assets_affected")
    if isinstance(assets, (str, int, float)):
        assets = [assets]

    return generate_explanation_text(
        vulnerability_id=str(vid),
        host_id=host,
        cvss=cvss,
        exploit_probability=prob,
        associated_path=path,
        individual_enablement=enablement,
        baseline_risk=float(r_before) if r_before is not None else None,
        patched_risk=float(r_after) if r_after is not None else None,
        risk_reduction_percent=float(r_reduc) if r_reduc is not None else None,
        critical_assets_affected=assets,
        choke_point_frequency=int(choke_count) if choke_count is not None else None,
    )
