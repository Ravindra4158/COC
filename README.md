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
  $$p = \min\left(0.95, \max\left(0.05, \frac{\text{cvss} - 2.0}{8.0}\right)\right)$$
- **Host Compromise Probability**:
  $$P_{\text{comp}}(H) = 1 - \prod_{v \in H} (1 - p_v)$$
- **Marginal Enablement ($\Delta P_{\text{comp}}$)**:
  Accounting for sibling vulnerability dilution:
  $$\Delta P_{\text{comp}}(v_i) = p_i \prod_{j \ne i} (1 - p_j)$$
  If an alternate vulnerability on the same host already provides easy access, mitigating $v_i$ alone yields low marginal enablement.

### 3. Synchronized Monte Carlo with Common Random Numbers (CRN)
- **Zero-Variance Counterfactuals**: A random matrix of exploit rolls $\mathbf{U} \in [0, 1)^{N \times 80}$ is drawn once per seed.
- **Deciding-Vote Masks**: For any vulnerability $v$, a host is compromised *only* because of $v$ in trial $t$ if and only if $v$ rolled a success and all siblings rolled a failure:
  $$\text{deciding}[t, v] = \text{host\_ok}[t] \land \neg \text{without\_v}[t]$$
- Replays BFS only across deciding trials, computing the exact causal risk reduction:
  $$\Delta \text{Risk}(v) = \text{Risk}_{\text{baseline}} - \text{Risk}_{\text{patched}}(v)$$
- **Budget Compliance**: Strictly bounds total simulation expenditure to $\le 4,000$ trials across the complete evaluation run.

### 4. Loop-Free Attack Path Witnesses
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
