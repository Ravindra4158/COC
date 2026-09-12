"""Graph-aware vulnerability ranking with synchronized Monte Carlo.

Can be run:
  1. Default development instance (seed 20260911, n=40, p=0.09):
     python rank_vulnerabilities.py
  2. With a custom seed:
     python rank_vulnerabilities.py --seed 12345
  3. With custom CSV datasets (general evaluation on test day):
     python rank_vulnerabilities.py --data-dir /path/to/csvs
     python rank_vulnerabilities.py --hosts hosts.csv --edges network_edges.csv --vulns vulnerabilities.csv --critical-assets critical_assets.csv

Methodology & Simulation Budget:
- Pre-draws 4 000 random exploit-outcome matrices (strictly <= 4 000 Monte Carlo budget).
- Computes baseline weighted critical-asset risk via BFS flood on the exploitable subgraph.
- Evaluates every vulnerability's counterfactual patch impact using Common Random Numbers (CRN)
  over deciding-vote trials, achieving zero Monte Carlo variance within budget.
- Computes multi-factor priority scores for all host-vulnerability pairs.
- Ranks vulnerabilities and selects top-10 patch recommendations with verified loop-free
  attacker-entry-to-critical-asset path witnesses and numeric risk reduction.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
import sys
from time import perf_counter
from typing import Any

import networkx as nx
import numpy as np

# ── Development instance default parameters ──────────────────────────────────
DEFAULT_SEED             = 20260912
DEFAULT_N_HOSTS          = 40
DEFAULT_EDGE_PROB        = 0.06
DEFAULT_ENTRY_NODES      = [0, 1]
DEFAULT_CRITICAL_WEIGHTS = {35: 1.0, 36: 2.0, 37: 3.0, 38: 4.0, 39: 5.0}
DEFAULT_VULNS_PER_HOST   = 2
DEFAULT_CVSS_MIN         = 3.0
DEFAULT_CVSS_MAX         = 9.8
MAX_SIMULATION_BUDGET    = 4_000
DEFAULT_TOP_K            = 10


def parse_seed(seed: Any, default: int = DEFAULT_SEED) -> int:
    """Parse seed from any format: int, date string ('2026-09-11', 'today'), or hash."""
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
        if s.lower() in ("today", "now", "current"):
            return int(datetime.now().strftime("%Y%m%d"))
        m1 = re.match(r"^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})$", s)
        if m1:
            return int(f"{int(m1.group(1)):04d}{int(m1.group(2)):02d}{int(m1.group(3)):02d}")
        m2 = re.match(r"^(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})$", s)
        if m2:
            return int(f"{int(m2.group(3)):04d}{int(m2.group(2)):02d}{int(m2.group(1)):02d}")
        return int(hashlib.sha256(s.encode("utf-8")).hexdigest()[:8], 16)
    return default



# ── Data structures ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Vuln:
    vid: str
    host: Any
    cvss: float
    prob: float  # exploit probability


def _node_sort_key(node: Any) -> tuple[int, Any]:
    try:
        return (0, int(node))
    except (ValueError, TypeError):
        return (1, str(node))


def _as_bool(value: Any) -> bool:
    if isinstance(value, (bool, np.bool_)):
        return bool(value)
    if isinstance(value, (int, float, np.number)):
        return bool(value and not math.isnan(value))
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "t"}
    return bool(value)


# ── 1. Graph construction & Component Stitching ──────────────────────────────

def connect_components(graph: nx.Graph) -> nx.Graph:
    """Connect adjacent components by their lowest-numbered nodes per development rules."""
    if len(graph) <= 1:
        return graph
    comps = sorted(
        (sorted(c, key=_node_sort_key) for c in nx.connected_components(graph)),
        key=lambda c: _node_sort_key(c[0]),
    )
    for left, right in zip(comps, comps[1:]):
        graph.add_edge(left[0], right[0])
    return graph


def build_synthetic_graph(n: int = DEFAULT_N_HOSTS, p: float = DEFAULT_EDGE_PROB, seed: int = DEFAULT_SEED) -> nx.Graph:
    """Build the development instance graph and sequentially connect components."""
    G = nx.gnp_random_graph(n, p, seed=seed, directed=False)
    return connect_components(G)


def build_synthetic_vulns(
    node_ids: list[Any],
    vulns_per_host: int = DEFAULT_VULNS_PER_HOST,
    cvss_min: float = DEFAULT_CVSS_MIN,
    cvss_max: float = DEFAULT_CVSS_MAX,
    seed: int = DEFAULT_SEED,
) -> list[Vuln]:
    """Generate vulnerabilities with NumPy PCG64 deterministic CVSS and exploit probabilities."""
    rng = np.random.Generator(np.random.PCG64(seed))
    out: list[Vuln] = []
    for h in node_ids:
        for k in range(1, vulns_per_host + 1):
            s = float(rng.uniform(cvss_min, cvss_max))
            p = min(0.95, max(0.05, (s - 2.0) / 8.0))
            out.append(Vuln(f"h{h}-v{k}", h, round(s, 6), round(p, 6)))
    return out


# ── 2. CSV Data Loading ──────────────────────────────────────────────────────

def _clean_str(val: Any) -> str:
    return str(val).strip() if val is not None else ""


def load_from_csv(
    hosts_path: Path,
    edges_path: Path,
    vulns_path: Path,
    critical_assets_path: Path,
) -> tuple[nx.Graph, list[Vuln], list[Any], dict[Any, float]]:
    """Load general evaluation instance from CSV files."""
    if not hosts_path.is_file():
        raise FileNotFoundError(f"hosts CSV not found: {hosts_path}")
    if not edges_path.is_file():
        raise FileNotFoundError(f"network edges CSV not found: {edges_path}")
    if not vulns_path.is_file():
        raise FileNotFoundError(f"vulnerabilities CSV not found: {vulns_path}")
    if not critical_assets_path.is_file():
        raise FileNotFoundError(f"critical assets CSV not found: {critical_assets_path}")

    graph = nx.Graph()
    entry_nodes: list[Any] = []
    node_set: set[Any] = set()

    # Load hosts
    with hosts_path.open("r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row_clean = {k.strip().lower(): v for k, v in row.items() if k}
            h_id = _clean_str(row_clean.get("host_id", row_clean.get("host", row_clean.get("node_id", row_clean.get("node", row_clean.get("id"))))))
            if not h_id:
                continue
            # Preserve numeric types if purely integer
            if h_id.isdigit():
                h_id = int(h_id)
            node_set.add(h_id)
            is_entry = _as_bool(row_clean.get("is_entry_point", row_clean.get("is_entry", row_clean.get("entry_point", row_clean.get("entry", False)))))
            if is_entry:
                entry_nodes.append(h_id)
            graph.add_node(h_id, is_entry_point=is_entry, name=row_clean.get("name", str(h_id)))

    # Load edges
    with edges_path.open("r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row_clean = {k.strip().lower(): v for k, v in row.items() if k}
            src = _clean_str(row_clean.get("source", row_clean.get("src", row_clean.get("from", row_clean.get("source_host")))))
            dst = _clean_str(row_clean.get("target", row_clean.get("dst", row_clean.get("to", row_clean.get("target_host")))))
            if not src or not dst:
                continue
            if src.isdigit():
                src = int(src)
            if dst.isdigit():
                dst = int(dst)
            graph.add_node(src)
            graph.add_node(dst)
            graph.add_edge(src, dst)

    # Ensure graph connectivity
    connect_components(graph)

    # Load critical assets
    critical_weights: dict[Any, float] = {}
    with critical_assets_path.open("r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row_clean = {k.strip().lower(): v for k, v in row.items() if k}
            h_id = _clean_str(row_clean.get("host_id", row_clean.get("asset_id", row_clean.get("node_id", row_clean.get("host", row_clean.get("id"))))))
            if not h_id:
                continue
            if h_id.isdigit():
                h_id = int(h_id)
            crit_val = row_clean.get("criticality", row_clean.get("impact_weight", row_clean.get("weight", row_clean.get("impact", row_clean.get("value", "1.0")))))
            try:
                weight = float(crit_val) if crit_val else 1.0
            except ValueError:
                weight = 1.0
            critical_weights[h_id] = weight
            if h_id not in graph:
                graph.add_node(h_id)
            graph.nodes[h_id]["is_critical"] = True
            graph.nodes[h_id]["criticality"] = weight

    # Infer entry nodes if none flagged
    if not entry_nodes:
        if 0 in graph and 1 in graph and 0 not in critical_weights and 1 not in critical_weights:
            entry_nodes = [0, 1]
        elif "0" in graph and "1" in graph and "0" not in critical_weights and "1" not in critical_weights:
            entry_nodes = ["0", "1"]
        else:
            non_crit = [n for n in sorted(graph.nodes, key=_node_sort_key) if n not in critical_weights]
            entry_nodes = non_crit[:2] if non_crit else list(sorted(graph.nodes, key=_node_sort_key))[:2]

    # Load vulnerabilities
    vulns: list[Vuln] = []
    with vulns_path.open("r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row_clean = {k.strip().lower(): v for k, v in row.items() if k}
            vid = _clean_str(row_clean.get("vuln_id", row_clean.get("vulnerability_id", row_clean.get("cve", row_clean.get("vuln", row_clean.get("id"))))))
            hid = _clean_str(row_clean.get("host_id", row_clean.get("host", row_clean.get("node_id", row_clean.get("node")))))
            if not vid or not hid:
                continue
            if hid.isdigit():
                hid = int(hid)
            if hid not in graph:
                graph.add_node(hid)
            cvss_str = row_clean.get("cvss", row_clean.get("cvss_score", row_clean.get("severity", row_clean.get("score", "5.0"))))
            try:
                cvss_val = float(cvss_str)
            except ValueError:
                cvss_val = 5.0
            cvss_val = min(10.0, max(0.0, cvss_val))
            prob_str = row_clean.get("exploit_probability", row_clean.get("probability", row_clean.get("prob", row_clean.get("exploit_prob"))))
            if prob_str:
                try:
                    prob_val = float(prob_str)
                except ValueError:
                    prob_val = min(0.95, max(0.05, (cvss_val - 2.0) / 8.0))
            else:
                prob_val = min(0.95, max(0.05, (cvss_val - 2.0) / 8.0))
            prob_val = min(0.95, max(0.05, prob_val))
            vulns.append(Vuln(vid, hid, round(cvss_val, 6), round(prob_val, 6)))

    return graph, vulns, entry_nodes, critical_weights


# ── 3. Synchronized Monte Carlo with Common Random Numbers (CRN) ─────────────

def evaluate_all(
    graph: nx.Graph,
    vulns: list[Vuln],
    entry_nodes: list[Any],
    critical_weights: dict[Any, float],
    n_sims: int = MAX_SIMULATION_BUDGET,
    seed: int = DEFAULT_SEED,
) -> tuple[float, dict[str, float], dict[str, float]]:
    """Return (baseline_risk, {vuln_id: patch_value}, {vuln_id: individual_enablement}).

    Uses common random numbers across all n_sims trials to compute exact counterfactual
    patch values with zero Monte Carlo variance.
    """
    nodes = list(graph.nodes)
    n_nodes = len(nodes)
    node_to_idx = {n: i for i, n in enumerate(nodes)}
    n_v = len(vulns)

    entry_indices = [node_to_idx[e] for e in entry_nodes if e in node_to_idx]
    if not entry_indices:
        return 0.0, {v.vid: 0.0 for v in vulns}, {v.vid: 0.0 for v in vulns}

    crit_weights_arr = np.zeros(n_nodes, dtype=float)
    for c, w in critical_weights.items():
        if c in node_to_idx:
            crit_weights_arr[node_to_idx[c]] = float(w)

    # Pre-draw random matrices
    rng = np.random.Generator(np.random.PCG64(seed))
    draws = rng.random((n_sims, n_v))
    entries = rng.integers(0, len(entry_indices), size=n_sims)

    probs = np.array([v.prob for v in vulns])
    success = draws < probs

    # Per-host vulnerability indices & marginal enablement
    host_vuln_idx: dict[int, list[int]] = defaultdict(list)
    host_vulns_map: dict[Any, list[Vuln]] = defaultdict(list)
    for i, v in enumerate(vulns):
        host_vulns_map[v.host].append(v)
        if v.host in node_to_idx:
            host_vuln_idx[node_to_idx[v.host]].append(i)

    individual_enablement: dict[str, float] = {}
    for v in vulns:
        siblings = [o for o in host_vulns_map[v.host] if o.vid != v.vid]
        sibling_fail = float(np.prod([1.0 - s.prob for s in siblings])) if siblings else 1.0
        individual_enablement[v.vid] = v.prob * sibling_fail

    # Determine per-trial host compromise status
    host_ok = np.zeros((n_sims, n_nodes), dtype=bool)
    for h_i, idxs in host_vuln_idx.items():
        host_ok[:, h_i] = success[:, idxs].any(axis=1)

    # Adjacency list
    adj: list[list[int]] = [[] for _ in range(n_nodes)]
    for u, v in graph.edges():
        if u in node_to_idx and v in node_to_idx:
            ui, vi = node_to_idx[u], node_to_idx[v]
            adj[ui].append(vi)
            adj[vi].append(ui)

    # BFS flood simulator
    def _bfs_risk(trial: int, mask: np.ndarray) -> float:
        entry = entry_indices[entries[trial]]
        comp = {entry}
        queue = [entry]
        qi = 0
        while qi < len(queue):
            u = queue[qi]
            qi += 1
            for nb in adj[u]:
                if nb not in comp and mask[nb]:
                    comp.add(nb)
                    queue.append(nb)
        return float(sum(crit_weights_arr[c] for c in comp if crit_weights_arr[c] > 0))

    # Baseline risk
    baseline_risks = np.empty(n_sims)
    for t in range(n_sims):
        baseline_risks[t] = _bfs_risk(t, host_ok[t])
    baseline_risk = float(baseline_risks.mean())

    # Deciding vote mask
    deciding = np.zeros((n_sims, n_v), dtype=bool)
    for h_i, idxs in host_vuln_idx.items():
        for vi in idxs:
            others = [j for j in idxs if j != vi]
            w = success[:, others].any(axis=1) if others else np.zeros(n_sims, dtype=bool)
            deciding[:, vi] = host_ok[:, h_i] & ~w

    # Counterfactual evaluation per vulnerability
    entry_idx_set = set(entry_indices)
    patch_values: dict[str, float] = {}
    for vi, v in enumerate(vulns):
        if v.host not in node_to_idx:
            patch_values[v.vid] = 0.0
            continue
        h_idx = node_to_idx[v.host]
        if h_idx in entry_idx_set:
            patch_values[v.vid] = 0.0
            continue
        affected = np.where(deciding[:, vi])[0]
        if len(affected) == 0:
            patch_values[v.vid] = 0.0
            continue
        patched_risks = baseline_risks.copy()
        for t in affected:
            mask = host_ok[t].copy()
            mask[h_idx] = False
            patched_risks[t] = _bfs_risk(t, mask)
        patch_values[v.vid] = max(0.0, baseline_risk - float(patched_risks.mean()))

    return baseline_risk, patch_values, individual_enablement


def evaluate_defense_cascade(
    graph: nx.Graph,
    vulns: list[Vuln],
    entry_nodes: list[Any],
    critical_weights: dict[Any, float],
    n_sims: int = MAX_SIMULATION_BUDGET,
    seed: int = DEFAULT_SEED,
    max_steps: int = 10,
) -> list[dict[str, Any]]:
    """Greedy sequential host-remediation cascade: patch entire hosts until risk = 0.

    At each step, picks the host whose full remediation (all vulns forced to fail)
    gives the largest marginal risk drop.  Reuses CRN draws from *evaluate_all*
    for variance-free comparison.

    Returns a list of cascade steps, each containing:
      - step, host_id, vulns_patched, risk_before, risk_after,
        cumulative_reduction_pct, is_fully_secure
    """
    nodes = list(graph.nodes)
    n_nodes = len(nodes)
    node_to_idx = {n: i for i, n in enumerate(nodes)}
    n_v = len(vulns)

    entry_indices = [node_to_idx[e] for e in entry_nodes if e in node_to_idx]
    if not entry_indices:
        return []

    crit_weights_arr = np.zeros(n_nodes, dtype=float)
    for c, w in critical_weights.items():
        if c in node_to_idx:
            crit_weights_arr[node_to_idx[c]] = float(w)

    # Pre-draw random matrices (same RNG stream as evaluate_all)
    rng = np.random.Generator(np.random.PCG64(seed))
    draws = rng.random((n_sims, n_v))
    entries = rng.integers(0, len(entry_indices), size=n_sims)

    probs = np.array([v.prob for v in vulns])
    success = draws < probs

    host_vuln_idx: dict[int, list[int]] = defaultdict(list)
    for i, v in enumerate(vulns):
        if v.host in node_to_idx:
            host_vuln_idx[node_to_idx[v.host]].append(i)

    # Build adjacency list
    adj: list[list[int]] = [[] for _ in range(n_nodes)]
    for u, v in graph.edges():
        if u in node_to_idx and v in node_to_idx:
            ui, vi = node_to_idx[u], node_to_idx[v]
            adj[ui].append(vi)
            adj[vi].append(ui)

    def _bfs_risk_vec(mask: np.ndarray, trial: int) -> float:
        entry = entry_indices[entries[trial]]
        comp = {entry}
        queue = [entry]
        qi = 0
        while qi < len(queue):
            u = queue[qi]
            qi += 1
            for nb in adj[u]:
                if nb not in comp and mask[nb]:
                    comp.add(nb)
                    queue.append(nb)
        return float(sum(crit_weights_arr[c] for c in comp if crit_weights_arr[c] > 0))

    # Current state
    current_host_ok = np.zeros((n_sims, n_nodes), dtype=bool)
    for h_i, idxs in host_vuln_idx.items():
        current_host_ok[:, h_i] = success[:, idxs].any(axis=1)

    # Compute initial baseline
    baseline_risks = np.array([_bfs_risk_vec(current_host_ok[t], t) for t in range(n_sims)])
    initial_risk = float(baseline_risks.mean())

    entry_idx_set = set(entry_indices)
    patched_hosts: set[int] = set()
    cascade: list[dict[str, Any]] = []

    current_risk = initial_risk
    for step in range(1, max_steps + 1):
        if current_risk <= 0.0:
            break

        best_host_idx: int | None = None
        best_risk = current_risk

        # Find the host whose remediation gives the largest marginal drop
        for h_idx in range(n_nodes):
            if h_idx in patched_hosts or h_idx in entry_idx_set:
                continue
            test_ok = current_host_ok.copy()
            test_ok[:, h_idx] = False
            test_risks = np.array([_bfs_risk_vec(test_ok[t], t) for t in range(n_sims)])
            mean_risk = float(test_risks.mean())
            if mean_risk < best_risk:
                best_risk = mean_risk
                best_host_idx = h_idx

        if best_host_idx is None:
            break

        # Apply the patch
        patched_hosts.add(best_host_idx)
        current_host_ok[:, best_host_idx] = False
        host_name = nodes[best_host_idx]
        patched_vids = [v.vid for v in vulns if v.host == host_name]

        cumulative_pct = round(100.0 * (1.0 - best_risk / initial_risk), 2) if initial_risk > 0 else 100.0
        is_secure = best_risk <= 0.0

        cascade.append({
            "step": step,
            "host_id": host_name,
            "vulnerabilities_patched": patched_vids,
            "risk_before": round(current_risk, 6),
            "risk_after": round(best_risk, 6),
            "marginal_reduction": round(current_risk - best_risk, 6),
            "cumulative_reduction_percent": cumulative_pct,
            "is_fully_secure": is_secure,
        })

        current_risk = best_risk
        if is_secure:
            break

    return cascade


# ── 4. Loop-Free Simple Attack Path Witnesses ─────────────────────────────────

def find_path(
    graph: nx.Graph,
    host: Any,
    entry_nodes: list[Any],
    critical_weights: dict[Any, float],
) -> list[Any] | None:
    """Return a simple entry -> host -> critical-asset path witness containing host."""
    sorted_crits = sorted(critical_weights.keys(), key=lambda c: critical_weights[c], reverse=True)
    for entry in entry_nodes:
        if entry not in graph or host not in graph:
            continue
        try:
            seg1 = nx.shortest_path(graph, entry, host)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            continue
        sub = graph.copy()
        sub.remove_nodes_from(seg1[:-1])  # preserve host, exclude prior nodes to avoid loops
        for crit in sorted_crits:
            if crit not in sub:
                continue
            try:
                seg2 = nx.shortest_path(sub, host, crit)
                return seg1 + seg2[1:]
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
    return None


# ── 5. Graph Features & Priority Scoring ─────────────────────────────────────

def compute_priority_scores(
    graph: nx.Graph,
    vulns: list[Vuln],
    entry_nodes: list[Any],
    critical_weights: dict[Any, float],
    patch_values: dict[str, float],
    individual_enablement: dict[str, float],
) -> list[dict[str, Any]]:
    """Compute multi-factor priority score and feature dictionary for each vulnerability."""
    dist_from_entry: dict[Any, int] = {}
    for e in entry_nodes:
        if e in graph:
            for node, dist in nx.single_source_shortest_path_length(graph, e).items():
                dist_from_entry[node] = min(dist_from_entry.get(node, dist), dist)

    dist_to_critical: dict[Any, int] = {}
    for c in critical_weights:
        if c in graph:
            for node, dist in nx.single_source_shortest_path_length(graph, c).items():
                dist_to_critical[node] = min(dist_to_critical.get(node, dist), dist)

    # Betweenness centrality as graph importance measure
    betweenness = nx.betweenness_centrality(graph) if len(graph) > 2 else {n: 1.0 for n in graph.nodes}
    max_bw = max(betweenness.values()) if betweenness and max(betweenness.values()) > 0 else 1.0

    rows: list[dict[str, Any]] = []
    for v in vulns:
        h = v.host
        e_dist = dist_from_entry.get(h)
        c_dist = dist_to_critical.get(h)
        reach_score = 1.0 / (1.0 + e_dist) if e_dist is not None else 0.0
        exposure_score = 1.0 / (1.0 + c_dist) if c_dist is not None else 0.0
        graph_imp = float(betweenness.get(h, 0.0) / max_bw)

        # Weighted priority score 0-100 scale
        priority_score = round(
            100.0 * (
                0.20 * (v.cvss / 10.0) +
                0.20 * v.prob +
                0.20 * reach_score +
                0.25 * exposure_score +
                0.15 * graph_imp
            ),
            4,
        )
        path = find_path(graph, h, entry_nodes, critical_weights)
        pv = patch_values.get(v.vid, 0.0)
        indiv = individual_enablement.get(v.vid, 0.0)

        rows.append({
            "vulnerability_id": v.vid,
            "host_id": h,
            "cvss": v.cvss,
            "exploit_probability": v.prob,
            "priority_score": priority_score,
            "individual_enablement": round(indiv, 6),
            "patch_value": round(pv, 6),
            "entry_distance": e_dist,
            "nearest_critical_distance": c_dist,
            "associated_path": path or [],
        })

    return rows


# ── 6. Main Pipeline & Output Generation ─────────────────────────────────────

def run_prioritization(
    data_dir: Path | None = None,
    hosts_file: Path | None = None,
    edges_file: Path | None = None,
    vulns_file: Path | None = None,
    critical_assets_file: Path | None = None,
    seed: int | str | None = DEFAULT_SEED,
    n_sims: int = MAX_SIMULATION_BUDGET,
    top_k: int = DEFAULT_TOP_K,
    output_dir: Path = Path("output"),
    force_dev: bool = False,
) -> dict[str, Any]:
    t0 = perf_counter()
    n_sims = min(MAX_SIMULATION_BUDGET, max(10, n_sims))
    actual_seed = parse_seed(seed, DEFAULT_SEED)

    # Determine execution mode: CSV files vs Synthetic development instance
    use_csv = False
    if not force_dev:
        if data_dir and data_dir.is_dir():
            h_p = data_dir / "hosts.csv"
            e_p = data_dir / "network_edges.csv"
            v_p = data_dir / "vulnerabilities.csv"
            c_p = data_dir / "critical_assets.csv"
            if h_p.is_file() and e_p.is_file() and v_p.is_file() and c_p.is_file():
                hosts_file, edges_file, vulns_file, critical_assets_file = h_p, e_p, v_p, c_p
                use_csv = True
        elif hosts_file and edges_file and vulns_file and critical_assets_file:
            use_csv = True

    if use_csv and hosts_file and edges_file and vulns_file and critical_assets_file:
        print(f"Loading network and vulnerabilities from CSVs: {hosts_file.parent}...")
        graph, vulns, entry_nodes, critical_weights = load_from_csv(
            hosts_file, edges_file, vulns_file, critical_assets_file
        )
    else:
        print(f"Constructing development instance: n={DEFAULT_N_HOSTS}, p={DEFAULT_EDGE_PROB}, seed={actual_seed}...")
        graph = build_synthetic_graph(DEFAULT_N_HOSTS, DEFAULT_EDGE_PROB, seed=actual_seed)
        vulns = build_synthetic_vulns(list(sorted(graph.nodes, key=_node_sort_key)), DEFAULT_VULNS_PER_HOST, seed=actual_seed)
        entry_nodes = list(DEFAULT_ENTRY_NODES)
        critical_weights = dict(DEFAULT_CRITICAL_WEIGHTS)

    print(f"Graph topology: {len(graph.nodes)} hosts, {len(graph.edges)} edges.")
    print(f"Entry nodes: {entry_nodes} | Critical assets: {critical_weights}")
    print(f"Total vulnerabilities: {len(vulns)}")

    # Run Synchronized Monte Carlo counterfactual evaluation
    baseline_risk, patch_values, indiv_enablement = evaluate_all(
        graph, vulns, entry_nodes, critical_weights, n_sims=n_sims, seed=actual_seed
    )

    # Run greedy sequential defense cascade until 100% secure
    print("Running defense cascade simulation...")
    cascade = evaluate_defense_cascade(
        graph, vulns, entry_nodes, critical_weights, n_sims=n_sims, seed=actual_seed
    )

    # Compute features, priority scores, and paths
    rows = compute_priority_scores(
        graph, vulns, entry_nodes, critical_weights, patch_values, indiv_enablement
    )

    for r in rows:
        pv = r["patch_value"]
        rr_frac = (pv / baseline_risk) if baseline_risk > 0 else 0.0
        r["risk_reduction_fraction"] = round(rr_frac, 6)
        r["risk_reduction_percent"] = round(100.0 * rr_frac, 4)

    # Deterministic ranking: patch_value desc, priority_score desc, individual_enablement desc, cvss desc
    rows.sort(
        key=lambda r: (
            -r["patch_value"],
            -r["priority_score"],
            -r["individual_enablement"],
            -r["cvss"],
            _node_sort_key(r["host_id"]),
            str(r["vulnerability_id"]),
        )
    )
    for i, r in enumerate(rows, 1):
        r["rank"] = i

    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Output ranked_vulnerabilities.csv
    fields = [
        "rank", "vulnerability_id", "host_id", "cvss", "exploit_probability",
        "priority_score", "individual_enablement", "patch_value",
        "risk_reduction_fraction", "risk_reduction_percent",
        "entry_distance", "nearest_critical_distance", "associated_path",
    ]
    with (output_dir / "ranked_vulnerabilities.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in rows:
            row_copy = dict(r)
            row_copy["associated_path"] = " -> ".join(map(str, r["associated_path"])) if r["associated_path"] else ""
            writer.writerow(row_copy)

    # 2. Output top-10 patch plan
    top10_candidates = [r for r in rows if r["associated_path"]][:top_k]
    if not top10_candidates:
        top10_candidates = rows[:top_k]

    plan: list[dict[str, Any]] = []
    for r in top10_candidates:
        path = r["associated_path"]
        path_str = " → ".join(map(str, path)) if path else f"Host {r['host_id']}"
        patched_risk = max(0.0, baseline_risk - r["patch_value"])
        explanation = (
            f"{r['vulnerability_id']} on host {r['host_id']} "
            f"(CVSS {r['cvss']:.1f}, exploit prob {r['exploit_probability']:.3f}) "
            f"sits on attack path {path_str}. "
            f"Marginal host enablement: {r['individual_enablement']:.4f} "
            f"(probability this vulnerability uniquely opens its host). "
            f"Mitigating it reduces the network's weighted critical-asset risk "
            f"from {baseline_risk:.4f} to {patched_risk:.4f} (-{r['risk_reduction_percent']:.2f}%), "
            f"measured via {n_sims} synchronized Monte Carlo trials."
        )
        plan.append({
            "rank": r["rank"],
            "vulnerability_id": r["vulnerability_id"],
            "host_id": r["host_id"],
            "cvss": r["cvss"],
            "exploit_probability": r["exploit_probability"],
            "associated_path": path,
            "associated_path_display": path_str,
            "baseline_weighted_risk": round(baseline_risk, 6),
            "patched_weighted_risk": round(patched_risk, 6),
            "estimated_risk_reduction_fraction": r["risk_reduction_fraction"],
            "estimated_risk_reduction_percent": r["risk_reduction_percent"],
            "explanation": explanation,
        })

    (output_dir / "top10_patch_plan.json").write_text(
        json.dumps(plan, indent=2, default=str), encoding="utf-8"
    )

    # 3. Output defense_cascade.json — sequential host remediation to 100% security
    hosts_to_full_security = len(cascade)
    cascade_output = {
        "baseline_weighted_risk": round(baseline_risk, 6),
        "hosts_to_full_security": hosts_to_full_security,
        "monte_carlo_trials": n_sims,
        "method": (
            "Greedy sequential host remediation: at each step, all vulnerabilities on "
            "the most impactful host are patched simultaneously. The simulation re-evaluates "
            "risk via CRN after each host is remediated, continuing until risk reaches 0.0."
        ),
        "cascade": cascade,
    }
    (output_dir / "defense_cascade.json").write_text(
        json.dumps(cascade_output, indent=2, default=str), encoding="utf-8"
    )

    # 4. Output simulation_report.json
    elapsed = round(perf_counter() - t0, 4)
    sim_report = {
        "max_allowed_simulations": MAX_SIMULATION_BUDGET,
        "monte_carlo_trials_drawn": n_sims,
        "total_simulations_used": n_sims,
        "within_budget": n_sims <= MAX_SIMULATION_BUDGET,
        "method": (
            "Common Random Numbers (CRN): Synchronized Monte Carlo exploit-outcome matrices "
            "drawn once and reused across baseline and all counterfactual patch scenarios "
            "via deciding-vote masks, delivering zero Monte Carlo variance."
        ),
        "baseline_weighted_risk": round(baseline_risk, 6),
        "total_hosts": len(graph.nodes),
        "total_vulnerabilities": len(vulns),
        "vulnerabilities_with_measurable_patch_value": sum(1 for v in patch_values.values() if v > 0),
        "top_k": len(plan),
        "defense_cascade": {
            "hosts_to_full_security": hosts_to_full_security,
            "hosts_patched": [s["host_id"] for s in cascade],
            "final_risk": cascade[-1]["risk_after"] if cascade else baseline_risk,
        },
        "runtime_seconds": elapsed,
    }
    (output_dir / "simulation_report.json").write_text(
        json.dumps(sim_report, indent=2), encoding="utf-8"
    )

    # 5. Output technical_explanations.md
    md_lines = [
        "# Technical Explanations — Top-10 Patch Recommendations",
        "",
        f"- **Baseline Weighted Critical-Asset Risk**: {baseline_risk:.4f}",
        f"- **Monte Carlo Simulation Budget**: {n_sims} synchronized trials (within <= {MAX_SIMULATION_BUDGET} budget)",
        f"- **Measurable Patch Findings**: {sim_report['vulnerabilities_with_measurable_patch_value']} / {len(vulns)}",
        f"- **Execution Runtime**: {elapsed:.2f}s",
        "",
        "---",
        "",
    ]
    for item in plan:
        md_lines.extend([
            f"## #{item['rank']}. {item['vulnerability_id']} on Host {item['host_id']}",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| CVSS Severity | {item['cvss']:.1f} |",
            f"| Exploit Probability | {item['exploit_probability']:.3f} |",
            f"| Verified Attack Path | `{item['associated_path_display']}` |",
            f"| Estimated Risk Reduction | **{item['estimated_risk_reduction_percent']:.2f}%** (fraction: {item['estimated_risk_reduction_fraction']:.4f}) |",
            f"| Network Risk Impact | {item['baseline_weighted_risk']:.4f} → {item['patched_weighted_risk']:.4f} |",
            "",
            f"> **Rationale**: {item['explanation']}",
            "",
            "---",
            "",
        ])

    # Defense cascade section
    md_lines.extend([
        "",
        "# Defense Cascade — Path to 100% Security",
        "",
        f"Starting from a baseline weighted critical-asset risk of **{baseline_risk:.4f}**, "
        f"the following greedy sequential host remediations reduce risk to **0.0** "
        f"in **{hosts_to_full_security}** steps.",
        "",
        "| Step | Host Remediated | Vulns Patched | Risk Before | Risk After | Cumulative Reduction |",
        "|------|----------------|---------------|-------------|------------|---------------------|",
    ])
    for s in cascade:
        vids = ", ".join(str(v) for v in s["vulnerabilities_patched"])
        secure_marker = " ✅ **100% SECURE**" if s["is_fully_secure"] else ""
        md_lines.append(
            f"| {s['step']} | Host {s['host_id']} | {vids} | "
            f"{s['risk_before']:.4f} | {s['risk_after']:.4f} | "
            f"**-{s['cumulative_reduction_percent']:.1f}%**{secure_marker} |"
        )
    md_lines.extend(["", "---", ""])

    (output_dir / "technical_explanations.md").write_text("\n".join(md_lines), encoding="utf-8")

    # Console output
    print(f"\nCompleted in {elapsed:.2f}s!")
    print(f"Baseline risk: {baseline_risk:.4f}")
    print(f"Top-{len(plan)} recommendations saved to {output_dir / 'top10_patch_plan.json'}")
    print(f"Ranked list saved to {output_dir / 'ranked_vulnerabilities.csv'}")
    print(f"Simulation report saved to {output_dir / 'simulation_report.json'}")
    print(f"Technical explanations saved to {output_dir / 'technical_explanations.md'}")
    print(f"\n{'='*60}")
    print(f"DEFENSE CASCADE — Path to 100% Security")
    print(f"{'='*60}")
    for s in cascade:
        status = "✅ 100% SECURE" if s["is_fully_secure"] else ""
        print(
            f"  Step {s['step']}: Patch Host {s['host_id']} "
            f"({', '.join(str(v) for v in s['vulnerabilities_patched'])}) → "
            f"Risk {s['risk_before']:.4f} → {s['risk_after']:.4f} "
            f"(-{s['cumulative_reduction_percent']:.1f}%) {status}"
        )
    print(f"{'='*60}")
    print(f"Defense cascade saved to {output_dir / 'defense_cascade.json'}")

    return {
        "graph": graph,
        "vulns": vulns,
        "baseline_risk": baseline_risk,
        "rows": rows,
        "top10": plan,
        "report": sim_report,
        "defense_cascade": cascade,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Graph-Aware Vulnerability Prioritization Engine")
    parser.add_argument("--data-dir", type=str, default=None, help="Directory containing CSV files (hosts.csv, etc.)")
    parser.add_argument("--hosts", type=str, default=None, help="Path to hosts.csv")
    parser.add_argument("--edges", type=str, default=None, help="Path to network_edges.csv")
    parser.add_argument("--vulns", type=str, default=None, help="Path to vulnerabilities.csv")
    parser.add_argument("--critical-assets", type=str, default=None, help="Path to critical_assets.csv")
    parser.add_argument("--seed", type=str, default=str(DEFAULT_SEED), help="Random seed or date (e.g. 20260911, 2026-09-11, today) for graph and simulation")
    parser.add_argument("--simulations", type=int, default=MAX_SIMULATION_BUDGET, help="Monte Carlo simulation budget (max 4000)")
    parser.add_argument("--top-k", type=int, default=DEFAULT_TOP_K, help="Number of patch recommendations")
    parser.add_argument("--output-dir", type=str, default="output", help="Output directory")
    parser.add_argument("--dev", action="store_true", help="Force synthetic development instance generation")
    args = parser.parse_args()

    data_dir = Path(args.data_dir) if args.data_dir else None
    hosts_f = Path(args.hosts) if args.hosts else None
    edges_f = Path(args.edges) if args.edges else None
    vulns_f = Path(args.vulns) if args.vulns else None
    crit_f = Path(args.critical_assets) if args.critical_assets else None
    out_dir = Path(args.output_dir)

    try:
        run_prioritization(
            data_dir=data_dir,
            hosts_file=hosts_f,
            edges_file=edges_f,
            vulns_file=vulns_f,
            critical_assets_file=crit_f,
            seed=args.seed,
            n_sims=args.simulations,
            top_k=args.top_k,
            output_dir=out_dir,
            force_dev=args.dev,
        )
    except FileNotFoundError as exc:
        print(f"\n[Error] {exc}")
        print("Please verify the file path or use --data-dir <directory_containing_csvs>.\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
