# Attack-Path-Aware Vulnerability Prioritization Engine (CY-02)

A modular, high-performance cybersecurity engine that simulates network attack propagation and prioritizes vulnerabilities based on their true contribution to attacker reachability toward weighted critical assets, rather than isolated CVSS scores.

Includes a complete **Python/FastAPI** backend and an **Enterprise Dark-Theme React Dashboard** inspired by modern SIEM and intelligence platforms (Datadog, Splunk, Palantir).

---

## 🎯 Architecture Overview

```
├── src/
│   ├── graph/           # Topology generation, component stitching, and loop-free path witnesses
│   │   ├── builder.py
│   │   ├── analysis.py
│   │   └── paths.py
│   ├── simulation/      # Unified Synchronized Monte Carlo engine (CRN, budget management)
│   │   ├── monte_carlo.py
│   │   ├── attacker.py
│   │   └── budget.py
│   ├── scoring/         # Sibling dilution (ΔP_comp), exposure, and priority scoring
│   │   ├── priority_score.py
│   │   ├── exploit_probability.py
│   │   ├── reachability.py
│   │   └── asset_impact.py
│   ├── optimization/    # Virtual patching, counterfactual evaluation, and deterministic ranking
│   │   ├── patch_impact.py
│   │   ├── candidate_filter.py
│   │   └── ranking.py
│   ├── explanation/     # Structured technical explanations and rationales
│   │   └── explainer.py
│   ├── data/            # Data loading, validation, and dev instance generation
│   │   ├── loader.py
│   │   └── validator.py
│   └── pipeline.py      # End-to-end analysis orchestration & artifact generation
│
├── app/                 # FastAPI service layer with dynamic state & caching
│   ├── main.py
│   ├── state.py
│   ├── schemas.py
│   └── routes/
│       ├── analysis.py
│       ├── network.py
│       ├── vulnerabilities.py
│       └── recommendations.py
│
├── frontend/            # React 18 + Cytoscape + Recharts dashboard UI
│   └── src/
│       ├── components/
│       │   ├── KeyMetrics.jsx
│       │   ├── NetworkGraph.jsx
│       │   ├── AttackSimulationPanel.jsx
│       │   ├── VulnerabilityRankingTable.jsx
│       │   ├── PatchImpactVisualization.jsx
│       │   ├── ExplainabilityPanel.jsx
│       │   └── NodeDetailDrawer.jsx
│       └── App.jsx
│
├── tests/               # 55 automated unit, integration, and architecture tests
└── output/              # Generated submission tables, plans, and metrics
```

## Project Purpose

This project answers a practical question: **which vulnerability should be fixed first when the attacker can move through a network?** It combines vulnerability severity, exploitability, topology, entry-point reachability, critical-asset exposure, attack-path frequency, and counterfactual patch impact.

The system has two ranking layers:

1. The analytic priority score ranks every finding using deterministic graph and vulnerability features.
2. The synchronized Monte Carlo pass evaluates a budgeted shortlist by virtually disabling one vulnerability at a time and measuring the resulting reduction in weighted critical-asset risk.

The result is a ranked vulnerability list, quantified patch recommendations, attack-path witnesses, machine-readable artifacts, a FastAPI service, and a React dashboard.

## End-to-End Pipeline

`src/pipeline.py` orchestrates the complete run:

1. **Load or generate data**: Use the configured development instance, or load the four CSV files from `data/raw/`. Caller-supplied `data` takes precedence when `run_analysis()` is used as a Python API.
2. **Normalize and validate**: Column aliases are normalized, numeric identifiers are harmonized, defaults are filled, and references are checked.
3. **Build the graph**: Hosts become nodes, network edges become links, vulnerabilities are attached to hosts, and criticality and entry-point metadata are added.
4. **Analyze topology**: Compute reachable nodes, downstream critical assets, shortest paths, bounded simple attack paths, host distances, and choke-point frequency.
5. **Run the baseline simulation**: Estimate host compromise and critical-asset reach probabilities with a reproducible NumPy `PCG64` generator.
6. **Score all findings**: Calculate the analytic priority score and attach a loop-free path witness where available.
7. **Pre-filter candidates**: Remove findings that cannot affect an entry-to-critical path, then retain the top analytic shortlist. The default shortlist is 30 findings and can be changed with `optimization.candidate_shortlist_size`.
8. **Evaluate patch impact**: Reuse common random numbers for the shortlist and calculate synchronized risk reductions within the hard 4,000-trial budget.
9. **Write artifacts and serve results**: Save CSV, JSON, and Markdown outputs and expose the cached result through the API.

## Repository Guide

- `src/data/`: CSV loading, column synonym handling, development-instance generation, type harmonization, and validation.
- `src/graph/`: Network construction, reachability analysis, shortest paths, bounded attack paths, and path witnesses.
- `src/scoring/`: Exploit probability, attacker reachability, critical-asset impact, and weighted priority scoring.
- `src/simulation/`: Baseline attack simulation, synchronized counterfactual evaluation, common random numbers, and budget validation.
- `src/optimization/`: Candidate filtering, virtual patching, patch-impact evaluation, and deterministic recommendation ranking.
- `src/explanation/`: Human-readable recommendation reasons based on measured impact and graph context.
- `app/`: FastAPI application, response schemas, cached state, serialization, and route handlers.
- `frontend/`: Vite-powered React dashboard with Cytoscape network visualization and Recharts impact views.
- `tests/`: Unit, integration, API, architecture, simulation, scoring, and pipeline tests.
- `output/`: Generated analysis artifacts. These files can be regenerated and should not be treated as source data.

## Input Data Contract

When `development_instance.enabled` is false, the application reads these files from `data/raw/`:

| File | Required columns | Purpose |
| :--- | :--- | :--- |
| `hosts.csv` | `host_id` | Host inventory. Optional `name` and `is_entry_point` are supported. |
| `vulnerabilities.csv` | `vuln_id`, `host_id`, `cvss` | Findings attached to hosts. `exploit_probability` is optional and derived from CVSS when absent. |
| `network_edges.csv` | `source`, `target` | Network connectivity between hosts. |
| `critical_assets.csv` | `host_id` | Critical targets. Optional `criticality` defaults to `1.0`. |

The loader accepts common aliases such as `host`, `node_id`, `cve`, `cvss_score`, `probability`, `src`, `dst`, `weight`, and `impact_weight`. IDs must be consistent across all files. The validator rejects duplicate vulnerability IDs, unknown host references, invalid CVSS values, invalid probabilities, and invalid criticality values.

For custom datasets, call `run_analysis(data={...})` with a mapping containing DataFrames named `hosts`, `vulnerabilities`, `network_edges`, and `critical_assets`. This is also the integration point for evaluator-supplied data.

## Configuration

The default `config.yaml` controls development data, simulation, scoring, and optimization:

| Setting | Default | Meaning |
| :--- | :--- | :--- |
| `development_instance.seed` | `20260911` | Reproducible graph and vulnerability generation seed. |
| `development_instance.topology.node_count` | `40` | Number of generated hosts, capped at 40. |
| `development_instance.topology.edge_probability` | `0.09` | Erdos-Renyi edge probability. |
| `development_instance.topology.directed` | `false` | Whether generated links are directed. |
| `simulation.max_simulations` | `4000` | Hard maximum budget. |
| `simulation.default_simulations` | `2000` | Baseline trial count, capped at half the hard maximum. |
| `simulation.max_attack_steps` | `50` | Maximum propagation steps for the baseline attacker. |
| `scoring.weights` | See formulas | Weights are normalized and must have a positive sum. |
| `optimization.top_k` | `10` | Number of recommendations written to the top-10 artifacts. |
| `optimization.patch_simulations` | `500` | Requested per-candidate allowance before remaining-budget allocation. |
| `optimization.candidate_shortlist_size` | `30` | Number of analytic candidates sent to counterfactual evaluation. |

The pipeline allocates the remaining budget across the shortlist. With the defaults, the baseline uses 2,000 trials and the 30-candidate shortlist receives at most 66 trials per candidate, keeping the conservative reported total at or below 4,000.

---

## 🧠 Core Methodology & Mathematical Formulations

### 1. Network Graph Construction
- **Erdős–Rényi Model**: Undirected random graph $G(n=40, p=0.09)$ seeded deterministically with `20260911`.
- **Sequential Component Stitching**: Disconnected components are sorted by their lowest node ID and connected sequentially through their lowest nodes ($c_i[0] \leftrightarrow c_{i+1}[0]$), guaranteeing a fully connected topology without modifying existing clusters.
- **Entry & Target Nodes**:
  - Entry points: Hosts `[0, 1]`.
  - Critical assets & weights: `{35: 1.0, 36: 2.0, 37: 3.0, 38: 4.0, 39: 5.0}`.

### 2. Sibling-Aware Vulnerability Modeling
- Exactly 2 vulnerabilities per host (80 findings total).
- CVSS scores sampled via NumPy `PCG64(seed=20260911)` uniformly from $[3.0, 9.8]$.
- Linear exploit probability rule:
  $$p_v = \min\left(0.95, \max\left(0.05, \frac{\mathrm{CVSS}(v) - 2.0}{8.0}\right)\right)$$
- **Host Compromise Probability**:
  $$P_{\text{comp}}(H) = 1 - \prod_{v \in V(H)} (1 - p_v)$$
- **Marginal Enablement ($\Delta P_{\text{comp}}$)**:
  Accounting for sibling vulnerability dilution:
  $$\Delta P_{\text{comp}}(v_i) = p_i \prod_{v_j \in V(H_i)\setminus\{v_i\}} (1 - p_j)$$
  If an alternate vulnerability on the same host already provides easy access, mitigating $v_i$ alone yields low marginal enablement.

### 3. Deterministic Graph Features and Priority Score
- Attacker reachability is the inverse of the shortest entry-point distance:
  $$A(h) = \frac{1}{1 + d_{\text{entry}}(h)}$$
  where unreachable hosts have $A(h)=0$.
- Critical-asset exposure combines simulated downstream breach probability and distance:
  $$E(h) = \min\left(1, 0.75\frac{\sum_{a \in D(h)} \bar{c}_a q_a}{\sum_{a \in C} \bar{c}_a} + \frac{0.25}{1 + d_{\text{critical}}(h)}\right)$$
  Here $D(h)$ is the set of downstream critical assets, $C$ is the complete critical-asset set, $\bar{c}_a=\min(1,c_a)$ is normalized criticality, and $q_a$ is the simulated probability of reaching asset $a$.
- Graph importance averages normalized attack-path frequency and normalized downstream asset count:
  $$G(h) = \frac{1}{2}\frac{f(h)}{\max_x f(x)} + \frac{1}{2}\frac{|D(h)|}{\max_x |D(x)|}$$
  Each ratio is treated as $0$ when its denominator is $0$.
- The final explainable priority score is a weighted sum on a 0–100 scale:
  $$S(v) = 100\left(0.20\,\hat{c}_v + 0.20\,p_v + 0.20\,A(h_v) + 0.25\,E(h_v) + 0.15\,G(h_v)\right)$$
  where $\hat{c}_v = \mathrm{CVSS}(v) / 10$.

### 4. Synchronized Monte Carlo with Common Random Numbers (CRN)
- **Zero-Variance Counterfactuals**: A random matrix of exploit rolls $\mathbf{U} \in [0, 1)^{N \times 80}$ is drawn once per seed.
- **Deciding-vote masks**: For vulnerability $v_i$ on host $h$, the trial is affected by patching $v_i$ only when it succeeds and every sibling fails:
  $$\mathrm{deciding}(t,v_i) = \mathrm{host\_ok}(t,h) \land \neg\left(\bigvee_{v_j \in V(h)\setminus\{v_i\}} \mathrm{success}(t,v_j)\right)$$
- Per-trial network risk is the sum of the criticality weights of reached assets:
  $$R_t = \sum_{a \in C} c_a\,\mathbf{1}[a\text{ is reached in trial }t]$$
- Baseline risk and the exact synchronized patch value are:
  $$R_{\text{baseline}} = \frac{1}{N}\sum_{t=1}^{N}R_t, \qquad \Delta R(v) = R_{\text{baseline}} - R_{\text{patched}}(v)$$
  The patch replay changes only deciding trials, reusing the same exploit rolls and entry-point draws.
- **Budget Compliance**: Strictly bounds total simulation expenditure to $\le 4,000$ trials across the complete evaluation run.

### 5. Loop-Free Attack Path Witnesses
Every recommended finding is paired with a verified, loop-free simple path witness:
$$\text{Entry} \longrightarrow \dots \longrightarrow \text{Host} \longrightarrow \dots \longrightarrow \text{Critical Asset}$$
guaranteeing that operators can trace and verify the attacker's causal trajectory.

---

## 🚀 Quick Start

### 1. Backend Setup & Tests

```bash
# Set up virtual environment
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run the complete test suite (55 tests)
PYTHONPATH=. .venv/bin/pytest tests/ -v

# Start the FastAPI backend server (port 8000)
.venv/bin/uvicorn app.main:app --reload --port 8000
```

### 2. Frontend Dashboard

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

The web UI will be available at **`http://localhost:5173`**.

The frontend reads the backend URL from `VITE_API_URL`; it defaults to `http://localhost:8000`. Start the backend before opening the dashboard. The UI loads the summary, network, vulnerability, and recommendation endpoints in parallel, then supports:

- dashboard metrics for baseline risk, reachability, simulations, and active patches;
- interactive Cytoscape network exploration with entry points, critical assets, and vulnerabilities;
- attack propagation exploration and simulation state visualization;
- sortable vulnerability ranking with CVSS, exploitability, reachability, exposure, and patch impact;
- patch-impact charts and explainability panels with path witnesses;
- virtual patch toggles, seed changes, refresh, and reset-to-default state.

For a frontend-only production preview:

```bash
cd frontend
npm run build
npm run preview
```

---

## 📊 API Reference

The FastAPI service exposes interactive Swagger docs at `http://localhost:8000/docs`:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Health check endpoint. |
| `GET` | `/analysis` | Current network analysis summary, baseline risk, and simulation counts. |
| `POST` | `/analysis/run` | Run or refresh simulation with optional disabled vulnerabilities or seed. |
| `POST` | `/analysis/reset` | Reset state to default baseline configuration. |
| `GET` | `/network` | Graph topology (nodes, edges, criticality, entry points, vulnerabilities). |
| `GET` | `/vulnerabilities`| All 80 vulnerabilities with CVSS, exploit probability, reachability, and scores. |
| `GET` | `/recommendations`| Top 10 prioritized recommendations with risk reduction and path witnesses. |

### API Examples

Check service health:

```bash
curl http://localhost:8000/health
```

Fetch the current analysis summary:

```bash
curl http://localhost:8000/analysis
```

Run a reproducible analysis with virtual patches enabled:

```bash
curl -X POST http://localhost:8000/analysis/run \
  -H 'Content-Type: application/json' \
  -d '{"disabled_vulnerabilities":["h12-v1","h27-v2"],"seed":20260911}'
```

The request returns the active patch IDs and seed. Query `/analysis`, `/vulnerabilities`, and `/recommendations` afterward to retrieve the refreshed result. Reset clears active patches and restores the default seed:

```bash
curl -X POST http://localhost:8000/analysis/reset
```

`/network` returns `nodes`, `edges`, and shortest attack paths. `/vulnerabilities` returns all scored findings, with patch fields set to zero for findings outside the measured shortlist. `/recommendations` returns the measured top recommendations. Errors are logged server-side and returned as an HTTP 500 response with a concise endpoint-specific message.

## State and Virtual Patching

The API stores one analysis result in an in-process cache protected by a thread lock. A request to `/analysis` reuses the cache; `/analysis/run`, a changed seed, or changed disabled-vulnerability IDs triggers a fresh pipeline run. Virtual patches do not mutate the source CSVs or generated vulnerability table: the selected findings receive exploit probability `0.0` for that run. `/analysis/reset` clears the cache, active patches, and active seed.

Seeds accept integers, date strings such as `2026-09-11`, the keywords `today`/`now`/`current`, or arbitrary strings that are converted to a deterministic hash. This makes alternate topology experiments reproducible.

---

## 📁 Generated Output Artifacts

Running the pipeline (`src/pipeline.py` or `GET /analysis`) automatically generates all standardized submission and audit files in the `output/` directory:

- **`output/ranked_vulnerabilities.csv`**: Complete ranking of all 80 host-vulnerability pairs with priority scores, enablement, and topological features.
- **`output/patch_impact.csv`**: Counterfactual risk reduction estimates for all candidate patches.
- **`output/top10_recommendations.csv`**: The top 10 recommended mitigations with verified path witnesses and quantified risk reductions.
- **`output/analysis_summary.json`**: Execution metadata, exact simulation count ($\le 4,000$), baseline risk, and runtime performance.
- **`output/explanations.json`**: Technical justifications for every top recommendation.
- **`output/attack_paths.json`**: Bounded entry-to-critical asset attack paths.
- **`output/simulation_results.csv`**: Per-critical-asset breach probabilities.

Additional metadata is included in `output/analysis_summary.json`, including host and vulnerability counts, reachable critical assets, baseline risk, attack-path count, candidate count, active seed, elapsed runtime, and the conservative simulation count.

## Budget Optimization

The hard budget applies to actual baseline and counterfactual evaluation work. The optimization strategy is:

1. Compute the analytic priority score for all findings without simulations.
2. Remove findings that are not on a reachable path to a critical asset.
3. Sort the remaining findings by analytic priority and retain a configurable shortlist.
4. Run one shared synchronized random-draw pass for that shortlist.
5. Allocate the remaining trials evenly across the shortlist, with the same draws reused for every patch candidate.

This concentrates simulation effort near the likely top-10 cutoff. The full scored table remains available, while measured patch values are populated for the shortlist and unmeasured findings retain their analytic ranking and zero measured patch impact. Increase `candidate_shortlist_size` when recall is more important than runtime, or decrease it for faster interactive refreshes.

## Running as a Python Module

The main orchestration function can be used without starting FastAPI:

```python
from src.pipeline import run_analysis

result = run_analysis(
  config_path="config.yaml",
  disabled_vulnerabilities=["h12-v1"],
  seed=20260911,
)

print(result["summary"])
print(result["top10"][["rank", "vulnerability_id", "patch_value"]])
```

Important returned keys include `graph`, `data`, `entry_points`, `critical_assets`, `graph_analysis`, `simulation`, `scored`, `candidates`, `patch_impact`, `top10`, and `summary`.

---

## 🧪 Testing & Verification

The codebase includes comprehensive test coverage across 20 test modules:

```bash
PYTHONPATH=. .venv/bin/pytest tests/ -v
```

Highlights:
- **`tests/test_architectural_engine.py`**: Validates graph connectivity, PCG64 bounds, $\Delta P_{\text{comp}}$ sibling dilution, strict 4,000 budget adherence, and Top 10 quality ($\Delta \text{Risk} > 0$).
- **`tests/test_dynamic_state.py`**: Tests interactive virtual patching, dynamic re-ranking, and cache resets via API.
- **`tests/test_patch_impact.py`**: Tests non-destructive virtual patching and access preservation under sibling findings.
- **`tests/test_priority_score.py`**: Tests score boundaries, graph context prioritization over raw CVSS, and asset exposure.

Run a focused slice while developing:

```bash
PYTHONPATH=. .venv/bin/pytest tests/test_pipeline.py tests/test_api.py -q
```

The tests cover data validation and generalization, graph connectivity and path witnesses, exploit probability, sibling dilution, reachability, scoring, Monte Carlo behavior, synchronized counterfactuals, budget limits, optimization, API serialization, dynamic state, and full pipeline artifacts.

## Troubleshooting

- **Frontend cannot connect**: start Uvicorn on port 8000, or set `VITE_API_URL` before `npm run dev`.
- **Missing input files**: either enable `development_instance` in `config.yaml` or provide all four required CSV files under `data/raw/`.
- **IDs do not match**: use the same host identifier values in `hosts.csv`, vulnerability `host_id`, edge endpoints, and critical-asset `host_id`.
- **Stale dashboard values**: call `POST /analysis/reset`, then refresh the dashboard. The API cache is process-local.
- **Slow refreshes**: lower `optimization.candidate_shortlist_size` or `simulation.default_simulations`; all simulation counts remain clamped by the 4,000 maximum.
- **Custom graph direction**: set `graph.directed` or `development_instance.topology.directed` deliberately; path reachability follows the resulting graph type.
