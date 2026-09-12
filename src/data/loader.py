from pathlib import Path
from collections.abc import Mapping

import networkx as nx
import numpy as np
import pandas as pd

from .validator import DataValidationError, REQUIRED_COLUMNS


def _load_csv(path: Path, name: str) -> pd.DataFrame:
    if not path.is_file():
        raise FileNotFoundError(f"Required data file not found: {path}")
    try:
        frame = pd.read_csv(path)
    except (OSError, pd.errors.ParserError) as exc:
        raise DataValidationError(f"Could not read {path}: {exc}") from exc
    frame.columns = [str(column).strip().lower() for column in frame.columns]
    missing = REQUIRED_COLUMNS[name] - set(frame.columns)
    if missing:
        raise DataValidationError(f"{path.name} is missing required columns: {sorted(missing)}")
    for column in frame.select_dtypes(include=["object", "string"]):
        frame[column] = frame[column].str.strip()
    return frame


def load_hosts(path: str | Path) -> pd.DataFrame:
    frame = _load_csv(Path(path), "hosts")
    if "name" not in frame.columns:
        frame["name"] = frame["host_id"].astype(str)
    return frame


def load_vulnerabilities(path: str | Path) -> pd.DataFrame:
    frame = _load_csv(Path(path), "vulnerabilities")
    if "exploit_probability" not in frame.columns and "cvss" in frame.columns:
        cvss = pd.to_numeric(frame["cvss"], errors="coerce")
        frame["exploit_probability"] = np.clip((cvss - 2.0) / 8.0, 0.05, 0.95)
    return frame


def load_network_edges(path: str | Path) -> pd.DataFrame:
    return _load_csv(Path(path), "network_edges")


def load_critical_assets(path: str | Path) -> pd.DataFrame:
    frame = _load_csv(Path(path), "critical_assets")
    if "criticality" not in frame.columns:
        frame["criticality"] = 1.0
    return frame


def load_all_data(data_dir: str | Path) -> dict[str, pd.DataFrame]:
    root = Path(data_dir)
    return {
        "hosts": load_hosts(root / "hosts.csv"),
        "vulnerabilities": load_vulnerabilities(root / "vulnerabilities.csv"),
        "network_edges": load_network_edges(root / "network_edges.csv"),
        "critical_assets": load_critical_assets(root / "critical_assets.csv"),
    }


load_raw_data = load_all_data


def generate_development_instance(instance: Mapping) -> dict[str, pd.DataFrame]:
    """Generate a configured graph-and-vulnerability instance from its rules.

    The generated tables deliberately use the same shape as CSV-loaded data so the
    rest of the application exercises one model and one ranking pipeline.
    """
    topology = instance["topology"]
    vulnerability_config = instance["vulnerabilities"]
    exploit_config = vulnerability_config["exploit_probability"]
    seed = int(instance["seed"])
    node_count = int(topology["node_count"])
    edge_probability = float(topology["edge_probability"])
    directed = bool(topology.get("directed", False))
    entry_points = {int(node) for node in instance["entry_points"]}
    critical_weights = {int(node): float(weight) for node, weight in instance["critical_asset_weights"].items()}
    findings_per_host = int(vulnerability_config["per_host"])
    cvss_min = float(vulnerability_config["cvss_min"])
    cvss_max = float(vulnerability_config["cvss_max"])
    probability_min = float(exploit_config["min"])
    probability_max = float(exploit_config["max"])
    probability_offset = float(exploit_config["offset"])
    probability_divisor = float(exploit_config["divisor"])
    if node_count <= 0 or not 0 <= edge_probability <= 1 or findings_per_host <= 0:
        raise ValueError("development-instance topology and vulnerability counts must be positive and valid")
    if not entry_points.issubset(range(node_count)) or not set(critical_weights).issubset(range(node_count)):
        raise ValueError("entry points and critical assets must be graph node IDs")

    graph = nx.gnp_random_graph(n=node_count, p=edge_probability, seed=seed, directed=directed)
    components = sorted((sorted(component) for component in nx.connected_components(graph)), key=lambda nodes: nodes[0])
    for left, right in zip(components, components[1:]):
        graph.add_edge(left[0], right[0])

    rng = np.random.Generator(np.random.PCG64(seed))
    vulnerabilities = []
    for host_id in range(node_count):
        for number in range(1, findings_per_host + 1):
            cvss = float(rng.uniform(cvss_min, cvss_max))
            vulnerabilities.append({
                "vuln_id": f"h{host_id}-v{number}",
                "host_id": host_id,
                "cvss": cvss,
                "exploit_probability": min(
                    probability_max,
                    max(probability_min, (cvss - probability_offset) / probability_divisor),
                ),
            })
    return {
        "hosts": pd.DataFrame([
            {"host_id": node, "name": f"Host {node}", "is_entry_point": node in entry_points}
            for node in sorted(graph.nodes)
        ]),
        "vulnerabilities": pd.DataFrame(vulnerabilities),
        "network_edges": pd.DataFrame(
            [{"source": source, "target": target} for source, target in sorted(graph.edges)]
        ),
        "critical_assets": pd.DataFrame([
            {"host_id": host_id, "criticality": weight} for host_id, weight in critical_weights.items()
        ]),
    }


def save_normalized_data(data: dict[str, pd.DataFrame], data_dir: str | Path) -> None:
    """Write normalized copies without changing the raw input files."""
    root = Path(data_dir)
    root.mkdir(parents=True, exist_ok=True)
    for name, frame in data.items():
        frame.to_csv(root / f"{name}.csv", index=False)
