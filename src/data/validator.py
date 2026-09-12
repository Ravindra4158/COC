import pandas as pd

REQUIRED_COLUMNS = {
    "hosts": {"host_id"},
    "vulnerabilities": {"vuln_id", "host_id", "cvss"},
    "network_edges": {"source", "target"},
    "critical_assets": {"host_id"},
}


class DataValidationError(ValueError):
    """Raised when an input dataset violates the Phase 1 data contract."""


def _require_columns(data: dict) -> None:
    for name, columns in REQUIRED_COLUMNS.items():
        if name not in data:
            raise DataValidationError(f"Missing dataset: {name}")
        missing = columns - set(data[name].columns)
        if missing:
            raise DataValidationError(f"{name} missing columns: {sorted(missing)}")


def validate_hosts(hosts: pd.DataFrame) -> None:
    if hosts["host_id"].isna().any() or (hosts["host_id"].astype(str).str.strip() == "").any():
        raise DataValidationError("hosts.csv contains a null or empty host ID")
    if hosts["host_id"].duplicated().any():
        raise DataValidationError("hosts.csv contains duplicate host IDs")
    if "criticality" in hosts:
        values = pd.to_numeric(hosts["criticality"], errors="coerce")
        if values.isna().any() or ((values < 0) | (values > 1)).any():
            raise DataValidationError("hosts.csv contains invalid criticality values")


def validate_vulnerabilities(vulnerabilities: pd.DataFrame, host_ids: set) -> None:
    if vulnerabilities["vuln_id"].isna().any() or vulnerabilities["vuln_id"].duplicated().any():
        raise DataValidationError("vulnerabilities.csv contains null or duplicate vulnerability IDs")
    if vulnerabilities["host_id"].isna().any():
        raise DataValidationError("vulnerabilities.csv contains a null host ID")
    unknown = set(vulnerabilities["host_id"]) - host_ids
    if unknown:
        raise DataValidationError(f"vulnerabilities.csv references unknown host IDs: {sorted(unknown)}")
    cvss = pd.to_numeric(vulnerabilities["cvss"], errors="coerce")
    if cvss.isna().any() or ((cvss < 0) | (cvss > 10)).any():
        raise DataValidationError("vulnerabilities.csv contains CVSS values outside the range 0 to 10")
    if "exploit_probability" in vulnerabilities:
        probability = pd.to_numeric(vulnerabilities["exploit_probability"], errors="coerce")
        if probability.isna().any() or ((probability < 0) | (probability > 1)).any():
            raise DataValidationError("vulnerabilities.csv contains exploit probabilities outside 0 to 1")


def validate_network_edges(edges: pd.DataFrame, host_ids: set) -> None:
    if edges[["source", "target"]].isna().any().any():
        raise DataValidationError("network_edges.csv contains a null source or destination")
    unknown = (set(edges["source"]) | set(edges["target"])) - host_ids
    if unknown:
        raise DataValidationError(f"network_edges.csv references unknown host IDs: {sorted(unknown)}")


def validate_critical_assets(assets: pd.DataFrame, host_ids: set) -> None:
    if assets["host_id"].isna().any():
        raise DataValidationError("critical_assets.csv contains a null host ID")
    unknown = set(assets["host_id"]) - host_ids
    if unknown:
        raise DataValidationError(f"critical_assets.csv references unknown host IDs: {sorted(unknown)}")
    if "criticality" in assets:
        values = pd.to_numeric(assets["criticality"], errors="coerce")
        if values.isna().any() or (values <= 0).any():
            raise DataValidationError("critical_assets.csv contains non-positive criticality values")


def validate_all(data: dict) -> None:
    _require_columns(data)
    validate_hosts(data["hosts"])
    raw_host_ids = set(data["hosts"]["host_id"])
    host_ids = raw_host_ids | {str(h) for h in raw_host_ids}
    for h in raw_host_ids:
        try:
            if str(h).isdigit():
                host_ids.add(int(h))
        except (ValueError, TypeError):
            pass
    validate_vulnerabilities(data["vulnerabilities"], host_ids)
    validate_network_edges(data["network_edges"], host_ids)
    validate_critical_assets(data["critical_assets"], host_ids)


validate_data = validate_all

