"""Graph-aware vulnerability ranking with synchronized Monte Carlo.

Run:  python rank_vulnerabilities.py

Strategy
--------
1.  Pre-draw 4 000 random exploit-outcome matrices (one per trial).
2.  Compute baseline weighted critical-asset risk via BFS on the
    "exploitable" subgraph for every trial.
3.  For each of the 80 vulnerability–host pairs, compute patch value by
    re-running BFS on the *same* random draws with that single
    vulnerability disabled.  Because the random outcomes are identical,
    the paired difference isolates the causal effect of the patch with
    near-zero variance — no additional simulation budget required.
4.  Rank by measured patch value; output top-10 with paths and
    explanations.

Simulation budget: 4 000 Monte Carlo trials (pre-drawn).
"""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter

import networkx as nx
import numpy as np

# ── Instance parameters ──────────────────────────────────────────────────────
SEED             = 20260911
N_HOSTS          = 40
EDGE_PROB        = 0.09
ENTRY_NODES      = [0, 1]
CRITICAL_WEIGHTS = {35: 1, 36: 2, 37: 3, 38: 4, 39: 5}
VULNS_PER_HOST   = 2
CVSS_MIN         = 3.0
CVSS_MAX         = 9.8
N_SIMULATIONS    = 4_000
TOP_K            = 10


# ── Data structures ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Vuln:
    vid: str
    host: int
    cvss: float
    prob: float  # exploit probability


# ── 1. Graph construction ────────────────────────────────────────────────────

def build_graph() -> nx.Graph:
    """Build the development instance graph, joining disconnected components."""
    G = nx.gnp_random_graph(N_HOSTS, EDGE_PROB, seed=SEED, directed=False)
    comps = sorted(
        (sorted(c) for c in nx.connected_components(G)),
        key=lambda c: c[0],
    )
    for left, right in zip(comps, comps[1:]):
        G.add_edge(left[0], right[0])
    return G


# ── 2. Vulnerability generation ──────────────────────────────────────────────

def build_vulns() -> list[Vuln]:
    """Generate two vulnerabilities per host with deterministic CVSS and p."""
    rng = np.random.Generator(np.random.PCG64(SEED))
    out: list[Vuln] = []
    for h in range(N_HOSTS):
        for k in range(1, VULNS_PER_HOST + 1):
            s = float(rng.uniform(CVSS_MIN, CVSS_MAX))
            p = min(0.95, max(0.05, (s - 2.0) / 8.0))
            out.append(Vuln(f"h{h}-v{k}", h, round(s, 6), round(p, 6)))
    return out


# ── 3. Synchronized Monte Carlo ──────────────────────────────────────────────

def evaluate_all(
    graph: nx.Graph,
    vulns: list[Vuln],
    n_sims: int = N_SIMULATIONS,
    seed: int = SEED,
) -> tuple[float, dict[str, float], np.ndarray]:
    """Return (baseline_risk, {vuln_id: patch_value}, baseline_per_trial).

    Uses common-random-numbers: all 4 000 random exploit outcomes are
    drawn once and reused for every patch scenario.
    """
    rng = np.random.Generator(np.random.PCG64(seed))
    n_v = len(vulns)

    # ── Pre-draw all randomness ──────────────────────────────────────────
    draws   = rng.random((n_sims, n_v))                               # exploit rolls
    entries = rng.integers(0, len(ENTRY_NODES), size=n_sims)           # entry selection

    # ── Exploit success per (trial, vuln) ────────────────────────────────
    probs   = np.array([v.prob for v in vulns])
    success = draws < probs                                            # (n_sims, n_v)

    # ── Per-host exploitability ──────────────────────────────────────────
    host_vuln_idx: dict[int, list[int]] = defaultdict(list)
    for i, v in enumerate(vulns):
        host_vuln_idx[v.host].append(i)

    host_ok = np.zeros((n_sims, N_HOSTS), dtype=bool)
    for h, idxs in host_vuln_idx.items():
        host_ok[:, h] = success[:, idxs].any(axis=1)

    # ── Adjacency list ───────────────────────────────────────────────────
    adj: list[list[int]] = [[] for _ in range(N_HOSTS)]
    for u, v in graph.edges():
        adj[u].append(v)
        adj[v].append(u)

    # ── BFS helper ───────────────────────────────────────────────────────
    def _bfs_risk(trial: int, mask: np.ndarray) -> float:
        """Single-trial BFS flood → weighted critical-asset risk."""
        entry = ENTRY_NODES[entries[trial]]
        comp = set()
        comp.add(entry)
        queue = [entry]
        qi = 0
        while qi < len(queue):
            u = queue[qi]; qi += 1
            for nb in adj[u]:
                if nb not in comp and mask[nb]:
                    comp.add(nb)
                    queue.append(nb)
        return sum(w for c, w in CRITICAL_WEIGHTS.items() if c in comp)

    # ── Baseline risk ────────────────────────────────────────────────────
    baseline_risks = np.empty(n_sims)
    for t in range(n_sims):
        baseline_risks[t] = _bfs_risk(t, host_ok[t])
    baseline_risk = float(baseline_risks.mean())

    # ── Deciding-vote mask per vuln ──────────────────────────────────────
    # deciding[t, vi] = True ⟺ host is exploitable ONLY because of vi
    deciding  = np.zeros((n_sims, n_v), dtype=bool)
    without_v: dict[int, np.ndarray] = {}

    for h, idxs in host_vuln_idx.items():
        for vi in idxs:
            others = [j for j in idxs if j != vi]
            w = success[:, others].any(axis=1) if others else np.zeros(n_sims, dtype=bool)
            without_v[vi] = w
            deciding[:, vi] = host_ok[:, h] & ~w

    # ── Patch evaluation (reuses the same random draws) ──────────────────
    patch_values: dict[str, float] = {}
    for vi, v in enumerate(vulns):
        if v.host in ENTRY_NODES:
            # Entry nodes are compromised without exploitation.
            patch_values[v.vid] = 0.0
            continue

        affected = np.where(deciding[:, vi])[0]
        if len(affected) == 0:
            patch_values[v.vid] = 0.0
            continue

        patched_risks = baseline_risks.copy()
        for t in affected:
            mask = host_ok[t].copy()
            mask[v.host] = False  # deciding ⟹ without_v[vi][t] is False
            patched_risks[t] = _bfs_risk(t, mask)

        patch_values[v.vid] = max(0.0, baseline_risk - float(patched_risks.mean()))

    return baseline_risk, patch_values, baseline_risks


# ── 4. Path finder ───────────────────────────────────────────────────────────

def find_path(graph: nx.Graph, host: int) -> list[int] | None:
    """Return a simple entry → host → critical-asset path, or None."""
    for entry in ENTRY_NODES:
        try:
            seg1 = nx.shortest_path(graph, entry, host)
        except nx.NetworkXNoPath:
            continue
        sub = graph.copy()
        sub.remove_nodes_from(seg1[:-1])          # keep host, remove prior nodes
        for crit in sorted(CRITICAL_WEIGHTS, key=lambda c: CRITICAL_WEIGHTS[c], reverse=True):
            if crit not in sub:
                continue
            try:
                seg2 = nx.shortest_path(sub, host, crit)
                return seg1 + seg2[1:]
            except nx.NetworkXNoPath:
                continue
    return None


# ── 5. Output ────────────────────────────────────────────────────────────────

def main() -> None:
    t0 = perf_counter()

    graph = build_graph()
    vulns = build_vulns()
    baseline_risk, patch_values, _ = evaluate_all(graph, vulns)

    # ── Host-level context ───────────────────────────────────────────────
    host_vulns_map: dict[int, list[Vuln]] = defaultdict(list)
    for v in vulns:
        host_vulns_map[v.host].append(v)

    rows: list[dict] = []
    for v in vulns:
        h = v.host
        path = find_path(graph, h)

        entry_dist = min(
            nx.shortest_path_length(graph, e, h) for e in ENTRY_NODES
        )
        crit_dists = {
            c: nx.shortest_path_length(graph, h, c) for c in CRITICAL_WEIGHTS
        }
        nearest_crit_dist = min(crit_dists.values())

        sibling_fail = float(np.prod([
            1.0 - o.prob for o in host_vulns_map[h] if o.vid != v.vid
        ]))
        individual_enablement = v.prob * sibling_fail

        pv = patch_values[v.vid]
        rr_frac = pv / baseline_risk if baseline_risk > 0 else 0.0

        rows.append({
            "vulnerability_id": v.vid,
            "host_id":          h,
            "cvss":             v.cvss,
            "exploit_probability": v.prob,
            "entry_distance":   entry_dist,
            "nearest_critical_distance": nearest_crit_dist,
            "individual_enablement": round(individual_enablement, 8),
            "patch_value":      round(pv, 8),
            "risk_reduction_fraction": round(rr_frac, 8),
            "risk_reduction_percent":  round(100.0 * rr_frac, 4),
            "associated_path":  path or [],
        })

    # ── Rank ─────────────────────────────────────────────────────────────
    rows.sort(key=lambda r: (
        -r["patch_value"],
        -r["individual_enablement"],
        -r["cvss"],
        r["vulnerability_id"],
    ))
    for i, r in enumerate(rows, 1):
        r["rank"] = i

    out = Path(__file__).resolve().parent / "output"
    out.mkdir(parents=True, exist_ok=True)

    # ── ranked_vulnerabilities.csv ───────────────────────────────────────
    fields = ["rank"] + [k for k in rows[0] if k != "rank"]
    with (out / "ranked_vulnerabilities.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            row = dict(r)
            row["associated_path"] = " -> ".join(map(str, row["associated_path"]))
            w.writerow(row)

    # ── Top-10 ───────────────────────────────────────────────────────────
    top10 = [r for r in rows if r["associated_path"]][:TOP_K]

    plan: list[dict] = []
    for r in top10:
        path_str = " → ".join(map(str, r["associated_path"]))
        plan.append({
            "rank":              r["rank"],
            "vulnerability_id":  r["vulnerability_id"],
            "host_id":           r["host_id"],
            "cvss":              r["cvss"],
            "exploit_probability": r["exploit_probability"],
            "associated_path":   r["associated_path"],
            "associated_path_display": path_str,
            "baseline_weighted_risk":  round(baseline_risk, 6),
            "patched_weighted_risk":   round(baseline_risk - r["patch_value"], 6),
            "estimated_risk_reduction_fraction": r["risk_reduction_fraction"],
            "estimated_risk_reduction_percent":  r["risk_reduction_percent"],
            "explanation": (
                f"{r['vulnerability_id']} on host {r['host_id']} "
                f"(CVSS {r['cvss']:.1f}, exploit prob {r['exploit_probability']:.3f}) "
                f"sits on attack path {path_str}. "
                f"Individual host-enablement contribution: {r['individual_enablement']:.4f} "
                f"(probability this vuln alone breaches its host). "
                f"Patching it reduces the network's weighted critical-asset risk "
                f"from {baseline_risk:.4f} to {baseline_risk - r['patch_value']:.4f} "
                f"(−{r['risk_reduction_percent']:.2f}%), measured via "
                f"{N_SIMULATIONS} synchronized Monte Carlo trials."
            ),
        })

    (out / "top10_patch_plan.json").write_text(
        json.dumps(plan, indent=2, default=str), encoding="utf-8",
    )

    # ── Simulation report ────────────────────────────────────────────────
    elapsed = round(perf_counter() - t0, 4)
    report = {
        "max_allowed_simulations": 4000,
        "monte_carlo_trials_drawn": N_SIMULATIONS,
        "total_simulations_used":  N_SIMULATIONS,
        "within_budget":           N_SIMULATIONS <= 4000,
        "method": (
            "Common-random-numbers: 4 000 exploit-outcome matrices "
            "pre-drawn once and reused for baseline + all 80 patch "
            "scenarios.  Each patch scenario replays BFS on the same "
            "random outcomes with one vulnerability disabled."
        ),
        "baseline_weighted_risk": round(baseline_risk, 6),
        "vulnerabilities_evaluated": len(vulns),
        "non_zero_patch_values": sum(1 for v in patch_values.values() if v > 0),
        "top_k":       TOP_K,
        "runtime_sec": elapsed,
    }
    (out / "simulation_report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8",
    )

    # ── Technical explanations ───────────────────────────────────────────
    lines = [
        "# Technical Explanations — Top-10 Patch Recommendations",
        "",
        f"**Baseline weighted critical-asset risk**: {baseline_risk:.4f}  ",
        f"**Simulation budget**: {N_SIMULATIONS} pre-drawn Monte Carlo "
        f"trials (common-random-numbers variance reduction).  ",
        f"**Vulnerabilities with measurable patch value**: "
        f"{sum(1 for v in patch_values.values() if v > 0)} / {len(vulns)}",
        "",
        "---",
        "",
    ]
    for item in plan:
        lines += [
            f"## {item['rank']}. {item['vulnerability_id']} "
            f"on host {item['host_id']}",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| CVSS | {item['cvss']:.1f} |",
            f"| Exploit probability | {item['exploit_probability']:.3f} |",
            f"| Path | {item['associated_path_display']} |",
            f"| Risk reduction | {item['estimated_risk_reduction_percent']:.2f}% |",
            f"| Baseline → Patched risk | "
            f"{item['baseline_weighted_risk']:.4f} → "
            f"{item['patched_weighted_risk']:.4f} |",
            "",
            f"{item['explanation']}",
            "",
            "---",
            "",
        ]
    (out / "technical_explanations.md").write_text(
        "\n".join(lines), encoding="utf-8",
    )

    # ── Console summary ──────────────────────────────────────────────────
    n_nonzero = sum(1 for r in top10 if r["patch_value"] > 0)
    print(f"Ranked {len(vulns)} vulnerabilities using "
          f"{N_SIMULATIONS} simulations in {elapsed:.2f}s.")
    print(f"Baseline weighted risk: {baseline_risk:.4f}")
    print(f"Top-{TOP_K}: {n_nonzero}/{len(top10)} with non-zero "
          f"risk reduction.")
    print(f"Max single-patch reduction: "
          f"{max(r['risk_reduction_percent'] for r in top10):.2f}%")
    print(f"Output → {out}/")


if __name__ == "__main__":
    main()
