# Graph-Aware Vulnerability Prioritization Submission

Standalone implementation of the supplied development-instance specification. It does not depend on or modify the existing CY-02 application.

## Run

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python rank_vulnerabilities.py
```

The command creates `output/` with:

- `ranked_vulnerabilities.csv` — all 80 host-vulnerability pairs
- `top10_patch_plan.json` — top-ten recommendations, a valid entry-to-critical path, and a numeric estimated reduction for each
- `simulation_report.json` — exact budget accounting
- `technical_explanations.md` — concise explanations for the highest-ranked items

## Budget and method

The method uses exactly 4,000 Monte Carlo trials: 2,000 baseline trials and 200 common-random-number trials for each of the ten recommended single-vulnerability patches. Ranking candidates are selected by a graph-aware analytical estimate before these simulations are allocated.

For each vulnerability `v` on host `h`, the structural estimate is:

```text
P(reach h from an entry) × P(v succeeds while h's sibling finding fails)
× max critical-asset importance reachable through h
÷ (1 + nearest critical-asset distance)
```

This credits an individual finding only for the portion of host compromise it uniquely enables, incorporates entry reachability, asset importance, and downstream proximity, and avoids spending the limited simulation budget independently on every one of 80 candidates. The reported patch reduction for a selected item is its Monte Carlo estimate: `(baseline_risk - patched_risk) / baseline_risk`.

The graph is made connected exactly as requested by ordering components by their minimum node and connecting adjacent component minima.
