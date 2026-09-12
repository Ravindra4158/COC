# Project Questions and Answers

This document is a standalone question bank for the Attack-Path-Aware Vulnerability Prioritization Engine. It progresses from basic usage to architecture, mathematics, simulation, optimization, API behavior, testing, and extension questions.

## 1. Basic Project Questions

### What problem does the project solve?

It determines which vulnerabilities should be remediated first by measuring their contribution to attacker reachability toward weighted critical assets. It combines CVSS, exploitability, network topology, attack paths, sibling vulnerabilities, and counterfactual patch impact.

### What is the main output?

The system produces a ranked vulnerability list, quantified patch recommendations, attack-path witnesses, simulation metrics, technical explanations, and a dashboard/API view of the results.

### Why is CVSS alone insufficient?

CVSS describes the severity of an individual finding. It does not describe whether the vulnerable host is reachable, whether the host lies on an attack path, whether sibling findings provide alternative access, or whether the host can lead to a critical asset.

### What technologies are used?

The backend uses Python, pandas, NumPy, NetworkX, FastAPI, Pydantic, and PyYAML. The frontend uses React, Vite, Cytoscape, and Recharts.

### What are the important project directories?

- `src/data/`: data loading and validation.
- `src/graph/`: graph construction, paths, and topology analysis.
- `src/scoring/`: vulnerability and graph scoring.
- `src/simulation/`: baseline and synchronized Monte Carlo simulation.
- `src/optimization/`: candidate filtering and patch impact.
- `src/explanation/`: recommendation explanations.
- `app/`: FastAPI service.
- `frontend/`: React dashboard.
- `tests/`: automated tests.
- `output/`: generated artifacts.

### How do I start the project?

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=. .venv/bin/pytest tests/ -v
.venv/bin/uvicorn app.main:app --reload --port 8000
```

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

The dashboard is available at `http://localhost:5173`, and the API is available at `http://localhost:8000`.

### What endpoints are available?

- `GET /health`: service health.
- `GET /analysis`: current analysis summary.
- `POST /analysis/run`: rerun analysis with optional patches and seed.
- `POST /analysis/reset`: clear state and restore defaults.
- `GET /network`: graph nodes, edges, and shortest paths.
- `GET /vulnerabilities`: all scored findings.
- `GET /recommendations`: top patch recommendations.
- `GET /docs`: interactive Swagger documentation.

## 2. Data Questions

### What is the default development instance?

It contains 40 hosts, two vulnerabilities per host, a deterministic graph generated with seed `20260911`, entry points `[0, 1]`, and critical assets with weights `{35: 1, 36: 2, 37: 3, 38: 4, 39: 5}`.

### Which CSV files are required for a custom dataset?

The raw data directory must contain:

| File | Required columns |
| :--- | :--- |
| `hosts.csv` | `host_id` |
| `vulnerabilities.csv` | `vuln_id`, `host_id`, `cvss` |
| `network_edges.csv` | `source`, `target` |
| `critical_assets.csv` | `host_id` |

### Which optional fields are supported?

Hosts can include `name` and `is_entry_point`. Vulnerabilities can include `exploit_probability`. Critical assets can include `criticality`.

### Can input column names use aliases?

Yes. The loader accepts aliases including `host`, `node_id`, `cve`, `cvss_score`, `probability`, `src`, `dst`, `weight`, and `impact_weight`.

### How is input data validated?

The validator checks required datasets and columns, duplicate IDs, null IDs, unknown host references, CVSS range, exploit-probability range, and criticality values.

### Can the project process evaluator-supplied data?

Yes. Call `run_analysis(data=...)` with DataFrames named `hosts`, `vulnerabilities`, `network_edges`, and `critical_assets`. Supplied data takes precedence over generated data.

### What happens if exploit probability is missing?

It is derived from CVSS using the configured bounded linear rule. If neither exploit probability nor CVSS is available, validation fails.

### Can numeric IDs and string IDs be mixed?

The loader harmonizes identifiers. Numeric datasets are converted to integers; non-numeric identifiers are normalized as strings. For reliable joins, use one consistent identifier style across all files.

## 3. Graph and Attack-Path Questions

### How is the network graph constructed?

Hosts become graph nodes and network-edge rows become graph edges. Vulnerabilities, criticality, names, and entry-point flags are attached to nodes.

### Is the default graph directed?

No. The generated development topology is undirected. Directed graphs are supported through configuration and use edge direction for reachability and paths.

### How are disconnected generated components handled?

The generated graph components are sorted by their lowest node ID and connected sequentially through those lowest nodes. This guarantees connectivity while preserving the existing component structure.

### What is an entry point?

An entry point is a host from which attacker propagation begins. The default entry points are hosts 0 and 1, unless host metadata or configuration provides valid alternatives.

### What is a critical asset?

A critical asset is a host whose compromise contributes weighted business or security impact. Its criticality weight is used in network-risk calculations.

### How are attack paths found?

The graph analysis computes reachable nodes, shortest paths, bounded simple paths, downstream critical assets, and hosts that frequently occur on attack paths.

### Why must paths be loop-free?

A loop-free path is easier to audit and represents a simple attacker trajectory without repeatedly visiting the same host. Recommendations can therefore show an operator a concrete entry-to-asset witness.

### What is a choke point?

A choke point is a host that appears frequently across attack paths. Its path frequency contributes to graph importance and helps identify strategically valuable remediation targets.

### What does downstream mean?

A critical asset is downstream of host $h$ when the graph contains a path from $h$ to that asset. The downstream set is used for exposure and candidate filtering.

## 4. Vulnerability and Scoring Questions

### How is exploit probability calculated?

For a vulnerability $v$ without an explicit probability:

$$p_v = \min\left(0.95, \max\left(0.05, \frac{\mathrm{CVSS}(v) - 2.0}{8.0}\right)\right)$$

The result is bounded between 0.05 and 0.95.

### What is host compromise probability?

For host $H$ with vulnerability set $V(H)$:

$$P_{\mathrm{comp}}(H) = 1 - \prod_{v \in V(H)} (1 - p_v)$$

This is the probability that at least one vulnerability succeeds.

### What is sibling dilution?

Sibling dilution means that one vulnerability has less marginal value when another vulnerability on the same host can provide the same access. For vulnerability $v_i$:

$$\Delta P_{\mathrm{comp}}(v_i) = p_i \prod_{v_j \in V(H_i) \setminus \{v_i\}} (1 - p_j)$$

### How is attacker reachability calculated?

For host $h$, reachability is based on the shortest distance from any entry point:

$$A(h) = \frac{1}{1 + d_{\mathrm{entry}}(h)}$$

Unreachable hosts receive zero reachability.

### How is critical-asset exposure calculated?

Exposure combines weighted downstream asset reach probability and distance to the nearest critical asset:

$$E(h) = \min\left(1, 0.75\frac{\sum_{a \in D(h)} \bar{c}_a q_a}{\sum_{a \in C} \bar{c}_a} + \frac{0.25}{1 + d_{\mathrm{critical}}(h)}\right)$$

Here $D(h)$ is the downstream asset set, $C$ is the complete asset set, $\bar{c}_a$ is normalized criticality, and $q_a$ is simulated asset reach probability.

### How is graph importance calculated?

Graph importance averages normalized path frequency and normalized downstream asset count:

$$G(h) = \frac{1}{2}\frac{f(h)}{\max_x f(x)} + \frac{1}{2}\frac{|D(h)|}{\max_x |D(x)|}$$

A ratio is zero when its denominator is zero.

### What is the final priority score?

The score is a weighted 0–100 value:

$$S(v) = 100\left(0.20\hat{c}_v + 0.20p_v + 0.20A(h_v) + 0.25E(h_v) + 0.15G(h_v)\right)$$

where $\hat{c}_v = \mathrm{CVSS}(v) / 10$.

### Why can a lower-CVSS finding rank higher?

It may have greater reachability, greater downstream exposure, higher path frequency, or stronger marginal enablement than the higher-CVSS finding.

### Are score weights configurable?

Yes. The five weights are configured under `scoring.weights`. They must be non-negative and have a positive total; the implementation normalizes them before scoring.

## 5. Simulation Questions

### What does a simulation trial do?

A trial samples exploit outcomes, selects an entry point, propagates through compromised hosts, and records compromised hosts and reached critical assets.

### What is Monte Carlo estimating?

It estimates host compromise probabilities, critical-asset reach probabilities, overall critical reach probability, and vulnerability success statistics from repeated trials.

### What is the baseline risk?

For trial $t$, risk is the sum of criticality values for reached assets:

$$R_t = \sum_{a \in C} c_a\mathbf{1}[a\text{ is reached in trial }t]$$

Baseline risk is the mean of $R_t$ over all trials:

$$R_{\mathrm{baseline}} = \frac{1}{N}\sum_{t=1}^{N}R_t$$

### What are common random numbers?

The synchronized evaluator draws exploit outcomes and entry-point choices once, then reuses them for the baseline and each patch scenario. This makes baseline and counterfactual results directly comparable.

### What is a deciding trial?

A trial is deciding for vulnerability $v_i$ when $v_i$ succeeds and all sibling vulnerabilities on the same host fail. Patching $v_i$ can change the host state only in such trials.

### How is patch value calculated?

For vulnerability $v$:

$$\Delta R(v) = R_{\mathrm{baseline}} - R_{\mathrm{patched}}(v)$$

Only deciding trials are replayed with the vulnerable host disabled. Negative values are clamped to zero.

### What is the simulation budget?

The hard maximum is 4,000 trials. The default baseline uses 2,000 trials, and the remaining budget is allocated across the analytic candidate shortlist.

### Does a direct synchronized evaluation test all vulnerabilities?

Yes, `evaluate_synchronized_monte_carlo()` can evaluate every vulnerability when no candidate set is provided. The pipeline uses a shortlist to spend the global budget more effectively.

### Why is the baseline run separate from the synchronized pass?

The baseline result supplies host and asset probabilities for scoring and reporting. The synchronized pass is optimized for comparable single-vulnerability counterfactual patch values.

## 6. Optimization Questions

### Why is candidate filtering needed?

Findings on unreachable hosts or hosts with no downstream critical asset cannot contribute to the target risk. Filtering avoids wasting counterfactual trials on them.

### How is the analytic shortlist selected?

The pipeline first keeps reachable attack-path candidates, then sorts them by analytic priority score, individual enablement, CVSS, and vulnerability ID as deterministic tie-breakers. The default shortlist size is 30.

### How is the budget divided?

After the baseline, the remaining budget is divided by the number of shortlisted candidates. The requested `patch_simulations` value is an upper bound, while the global 4,000 limit takes precedence.

### Why not simulate all candidates equally?

Most candidates are far from the recommendation cutoff. Equal allocation gives many trials to decisions that are already obvious. Shortlisting concentrates trials where ranking changes are plausible.

### Is adaptive refinement implemented?

Not currently. The current approach uses deterministic equal allocation across the shortlist. An advanced extension could identify candidates whose confidence intervals overlap near rank 10 and allocate additional trials only to them.

### What happens to findings outside the shortlist?

They remain in the complete analytic ranking. Their measured patch value is zero because no counterfactual simulation was spent on them.

### Can I make the shortlist larger?

Yes. Set `optimization.candidate_shortlist_size`. A larger shortlist improves recall but leaves fewer trials per candidate under the same hard budget.

## 7. API and Dashboard Questions

### Is API state persistent?

No. State is an in-process cache. Restarting the backend clears patches, seed overrides, and cached results.

### How do I run a virtual patch through the API?

```bash
curl -X POST http://localhost:8000/analysis/run \
  -H 'Content-Type: application/json' \
  -d '{"disabled_vulnerabilities":["h12-v1"],"seed":20260911}'
```

### How do I reset virtual patches?

```bash
curl -X POST http://localhost:8000/analysis/reset
```

### How does the dashboard load data?

It requests analysis, network, vulnerability, and recommendation data in parallel. The dashboard then renders metrics, Cytoscape graph views, simulation panels, ranking tables, patch visualizations, and explanation panels.

### How do I configure the frontend API URL?

Set `VITE_API_URL` before starting Vite. If it is not set, the frontend uses `http://localhost:8000`.

### What happens when the backend is unavailable?

The frontend displays a connection error. Start Uvicorn, verify port 8000, and reload the dashboard.

## 8. Testing and Engineering Questions

### How do I run all tests?

```bash
PYTHONPATH=. .venv/bin/pytest tests/ -v
```

### What do the architecture tests verify?

They verify graph connectivity, deterministic random generation, sibling dilution, simulation budget compliance, positive top recommendations, and major pipeline invariants.

### What do the dynamic-state tests verify?

They verify virtual patch updates, reranking, cache refreshes, seed changes, and reset behavior through the API state layer.

### How do I debug an unexpected recommendation?

Inspect these files in order:

1. `output/analysis_summary.json`
2. `output/attack_paths.json`
3. `output/ranked_vulnerabilities.csv`
4. `output/patch_impact.csv`
5. `output/explanations.json`

Check the active seed, active patches, host path, sibling vulnerabilities, candidate shortlist, baseline risk, and simulation count.

### What are the main correctness invariants?

Host references must be valid, probabilities must remain within their allowed ranges, paths must be loop-free, virtual patches must not mutate source data, rankings must have deterministic tie-breaking, and total simulation usage must not exceed 4,000.

### How do I add a scoring feature?

Implement it in the owning scoring module, expose it in the scored row, update configuration if it needs a weight, add focused unit tests, and update the README and generated-artifact documentation.

### How do I add an API field?

Update the route payload, Pydantic response schema when applicable, serialization handling, frontend service/types if needed, and API tests.

### How do I add a generated artifact?

Write it from `run_analysis()`, document its schema and purpose, and test both normal output and empty-candidate behavior.

## 9. Advanced Review Questions

### Why does the system use both analytic scoring and simulation?

Analytic scoring is cheap and covers every finding. Simulation is more causally faithful but expensive. Combining them gives complete coverage plus high-quality counterfactual measurements for the most relevant candidates.

### What does synchronized evaluation improve?

It removes much of the noise caused by comparing independently sampled simulations. Since every scenario sees the same random draws, the measured difference is attributable to the vulnerability patch more directly.

### Why does sibling dilution matter for remediation?

Patching one of two equivalent access vulnerabilities may leave the host almost as reachable as before. The marginal enablement term and deciding-trial mask model this redundancy instead of awarding full credit to both findings.

### What is the difference between asset exposure and network risk?

Asset exposure is a normalized feature used in analytic priority scoring. Network risk is a weighted aggregate used for counterfactual patch impact. Exposure caps criticality for feature comparability; risk preserves configured asset weights.

### What are the limitations of the current model?

The API cache is process-local, adaptive confidence-based allocation is not implemented, findings outside the shortlist do not receive measured patch values, and the development generator is intentionally capped at 40 hosts.

### What would be a useful next research improvement?

Add confidence intervals and adaptive successive-elimination allocation, calibrate analytic scores against measured patch values, support persistent job storage, and evaluate ranking quality with metrics such as NDCG@20 and Spearman correlation on labeled scenarios.

### What should a production deployment add?

Use a persistent job/result store, authentication and authorization, request validation limits, structured logging, worker coordination, artifact versioning, observability, and a clear policy for importing and retaining vulnerability data.
