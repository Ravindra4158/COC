import re
import hashlib
from datetime import datetime
from pathlib import Path
from collections.abc import Mapping
from typing import Any

import networkx as nx
import numpy as np
import pandas as pd

from .validator import DataValidationError, REQUIRED_COLUMNS

DATASET_SYNONYMS = {
    "hosts": {
        "host_id": ["host_id", "host", "node_id", "node", "id", "hostname", "asset_id"],
        "is_entry_point": ["is_entry_point", "is_entry", "entry_point", "entry", "is_ingress"],
        "criticality": ["criticality", "weight", "impact_weight", "impact", "value"],
        "name": ["name", "label", "hostname"],
    },
    "vulnerabilities": {
        "vuln_id": ["vuln_id", "vulnerability_id", "cve", "vuln", "id"],
        "host_id": ["host_id", "host", "node_id", "node"],
        "cvss": ["cvss", "cvss_score", "severity", "score", "cvss_base_score"],
        "exploit_probability": ["exploit_probability", "exploit_prob", "probability", "prob"],
    },
    "network_edges": {
        "source": ["source", "src", "from", "source_host", "source_node"],
        "target": ["target", "dst", "to", "target_host", "target_node", "destination"],
    },
    "critical_assets": {
        "host_id": ["host_id", "asset_id", "node_id", "host", "node", "id"],
        "criticality": ["criticality", "weight", "impact_weight", "impact", "value", "score"],
    },
}


def parse_seed(seed: Any, default: int = 20260911) -> int:
    """Parse seed from any possible format (int, date string, keywords like 'today', hashes)."""
    if seed is None or seed == "":
        return default
    if isinstance(seed, (int, np.integer)):
        return int(seed)
    if isinstance(seed, float):
        return int(seed)
    if isinstance(seed, str):
        s = seed.strip()
        try:
            return int(s)
        except ValueError:
            pass
        # Special keywords
        if s.lower() in ("today", "now", "current"):
            return int(datetime.now().strftime("%Y%m%d"))
        # Date formats like YYYY-MM-DD, YYYY/MM/DD, YYYY.MM.DD
        m1 = re.match(r"^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})$", s)
        if m1:
            return int(f"{int(m1.group(1)):04d}{int(m1.group(2)):02d}{int(m1.group(3)):02d}")
        # Date formats like DD-MM-YYYY, DD/MM/YYYY
        m2 = re.match(r"^(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})$", s)
        if m2:
            return int(f"{int(m2.group(3)):04d}{int(m2.group(2)):02d}{int(m2.group(1)):02d}")
        # Deterministic string hash fallback (positive 31-bit integer)
        h = int(hashlib.sha256(s.encode("utf-8")).hexdigest()[:8], 16)
        return h
    return default


def _load_csv(path: Path, name: str) -> pd.DataFrame:
    if not path.is_file():
        raise FileNotFoundError(f"Required data file not found: {path}")
    try:
        frame = pd.read_csv(path)
    except (OSError, pd.errors.ParserError) as exc:
        raise DataValidationError(f"Could not read {path}: {exc}") from exc
    frame.columns = [str(column).strip().lower() for column in frame.columns]

    # Map column synonyms for this dataset
    synonyms = DATASET_SYNONYMS.get(name, {})
    renames = {}
    for canon, syns in synonyms.items():
        if canon not in frame.columns:
            for syn in syns:
                if syn in frame.columns and syn not in renames:
                    renames[syn] = canon
                    break
    if renames:
        frame = frame.rename(columns=renames)

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
    if "cvss" in frame.columns:
        cvss = pd.to_numeric(frame["cvss"], errors="coerce").fillna(5.0)
        frame["cvss"] = np.clip(cvss, 0.0, 10.0)
    if "exploit_probability" not in frame.columns and "cvss" in frame.columns:
        frame["exploit_probability"] = np.clip((frame["cvss"] - 2.0) / 8.0, 0.05, 0.95)
    elif "exploit_probability" in frame.columns:
        probs = pd.to_numeric(frame["exploit_probability"], errors="coerce")
        if "cvss" in frame.columns:
            probs = probs.fillna(np.clip((frame["cvss"] - 2.0) / 8.0, 0.05, 0.95))
        else:
            probs = probs.fillna(0.5)
        frame["exploit_probability"] = np.clip(probs, 0.05, 0.95)
    return frame


def load_network_edges(path: str | Path) -> pd.DataFrame:
    return _load_csv(Path(path), "network_edges")


def load_critical_assets(path: str | Path) -> pd.DataFrame:
    frame = _load_csv(Path(path), "critical_assets")
    if "criticality" not in frame.columns:
        frame["criticality"] = 1.0
    else:
        frame["criticality"] = pd.to_numeric(frame["criticality"], errors="coerce").fillna(1.0)
    return frame


def harmonize_data_types(data: dict[str, pd.DataFrame]) -> dict[str, pd.DataFrame]:
    """Harmonize host ID types across datasets so ints and numeric strings match cleanly."""
    hosts = data["hosts"]
    edges = data["network_edges"]
    vulns = data["vulnerabilities"]
    crits = data["critical_assets"]

    all_numeric = True
    for col_series in [hosts.get("host_id"), edges.get("source"), edges.get("target"), vulns.get("host_id"), crits.get("host_id")]:
        if col_series is not None:
            for val in col_series.dropna():
                if isinstance(val, (int, np.integer)):
                    continue
                s = str(val).strip()
                if not s.isdigit():
                    all_numeric = False
                    break
            if not all_numeric:
                break

    if all_numeric:
        hosts["host_id"] = hosts["host_id"].astype(int)
        edges["source"] = edges["source"].astype(int)
        edges["target"] = edges["target"].astype(int)
        vulns["host_id"] = vulns["host_id"].astype(int)
        crits["host_id"] = crits["host_id"].astype(int)
    else:
        hosts["host_id"] = hosts["host_id"].astype(str).str.strip()
        edges["source"] = edges["source"].astype(str).str.strip()
        edges["target"] = edges["target"].astype(str).str.strip()
        vulns["host_id"] = vulns["host_id"].astype(str).str.strip()
        crits["host_id"] = crits["host_id"].astype(str).str.strip()

    return data


def load_all_data(data_dir: str | Path) -> dict[str, pd.DataFrame]:
    root = Path(data_dir)
    data = {
        "hosts": load_hosts(root / "hosts.csv"),
        "vulnerabilities": load_vulnerabilities(root / "vulnerabilities.csv"),
        "network_edges": load_network_edges(root / "network_edges.csv"),
        "critical_assets": load_critical_assets(root / "critical_assets.csv"),
    }
    return harmonize_data_types(data)


load_raw_data = load_all_data


def generate_development_instance(instance: Mapping) -> dict[str, pd.DataFrame]:
    """Generate a configured graph-and-vulnerability instance from its rules.

    The generated tables deliberately use the same shape as CSV-loaded data so the
    rest of the application exercises one model and one ranking pipeline.
    """
    topology = instance["topology"]
    vulnerability_config = instance["vulnerabilities"]
    exploit_config = vulnerability_config["exploit_probability"]
    seed = parse_seed(instance.get("seed", 20260911))
    node_count = min(40, max(1, int(topology.get("node_count", 40))))
    edge_probability = float(topology.get("edge_probability", 0.09))
    directed = bool(topology.get("directed", False))

    raw_entries = instance.get("entry_points", [0, 1])
    entry_points = {int(node) for node in raw_entries if int(node) < node_count}
    if not entry_points:
        entry_points = {0, 1} if node_count > 1 else {0}

    raw_crits = instance.get("critical_asset_weights", {35: 1, 36: 2, 37: 3, 38: 4, 39: 5})
    critical_weights = {int(node): float(weight) for node, weight in raw_crits.items() if int(node) < node_count}
    if not critical_weights and node_count > 0:
        critical_weights = {node_count - 1: 5.0}

    findings_per_host = max(1, int(vulnerability_config.get("per_host", 2)))
    cvss_min = float(vulnerability_config.get("cvss_min", 3.0))
    cvss_max = float(vulnerability_config.get("cvss_max", 9.8))
    probability_min = float(exploit_config.get("min", 0.05))
    probability_max = float(exploit_config.get("max", 0.95))
    probability_offset = float(exploit_config.get("offset", 2.0))
    probability_divisor = float(exploit_config.get("divisor", 8.0))

    graph = nx.gnp_random_graph(n=node_count, p=edge_probability, seed=seed, directed=directed)
    if len(graph) > 1:
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
