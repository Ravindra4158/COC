# Technical Explanations — Top-10 Patch Recommendations

- **Baseline Weighted Critical-Asset Risk**: 0.8911
- **Monte Carlo Simulation Budget**: 4000 synchronized trials (within <= 4000 budget)
- **Measurable Patch Findings**: 2 / 4
- **Execution Runtime**: 0.03s

---

## #1. v3 on Host h3

| Metric | Value |
|---|---|
| CVSS Severity | 8.5 |
| Exploit Probability | 0.900 |
| Verified Attack Path | `h1 → h2 → h3 → h4` |
| Estimated Risk Reduction | **100.00%** (fraction: 1.0000) |
| Network Risk Impact | 0.8911 → 0.0000 |

> **Rationale**: v3 on host h3 (CVSS 8.5, exploit prob 0.900) sits on attack path h1 → h2 → h3 → h4. Marginal host enablement: 0.9000 (probability this vulnerability uniquely opens its host). Mitigating it reduces the network's weighted critical-asset risk from 0.8911 to 0.0000 (-100.00%), measured via 4000 synchronized Monte Carlo trials.

---

## #2. v4 on Host h4

| Metric | Value |
|---|---|
| CVSS Severity | 5.0 |
| Exploit Probability | 0.500 |
| Verified Attack Path | `h1 → h2 → h3 → h4` |
| Estimated Risk Reduction | **36.01%** (fraction: 0.3601) |
| Network Risk Impact | 0.8911 → 0.5702 |

> **Rationale**: v4 on host h4 (CVSS 5.0, exploit prob 0.500) sits on attack path h1 → h2 → h3 → h4. Marginal host enablement: 0.5000 (probability this vulnerability uniquely opens its host). Mitigating it reduces the network's weighted critical-asset risk from 0.8911 to 0.5702 (-36.01%), measured via 4000 synchronized Monte Carlo trials.

---

## #3. v2 on Host h2

| Metric | Value |
|---|---|
| CVSS Severity | 6.0 |
| Exploit Probability | 0.600 |
| Verified Attack Path | `h1 → h2 → h3 → h4` |
| Estimated Risk Reduction | **0.00%** (fraction: 0.0000) |
| Network Risk Impact | 0.8911 → 0.8911 |

> **Rationale**: v2 on host h2 (CVSS 6.0, exploit prob 0.600) sits on attack path h1 → h2 → h3 → h4. Marginal host enablement: 0.6000 (probability this vulnerability uniquely opens its host). Mitigating it reduces the network's weighted critical-asset risk from 0.8911 to 0.8911 (-0.00%), measured via 4000 synchronized Monte Carlo trials.

---

## #4. v1 on Host h1

| Metric | Value |
|---|---|
| CVSS Severity | 7.5 |
| Exploit Probability | 0.800 |
| Verified Attack Path | `h1 → h2 → h3 → h4` |
| Estimated Risk Reduction | **0.00%** (fraction: 0.0000) |
| Network Risk Impact | 0.8911 → 0.8911 |

> **Rationale**: v1 on host h1 (CVSS 7.5, exploit prob 0.800) sits on attack path h1 → h2 → h3 → h4. Marginal host enablement: 0.8000 (probability this vulnerability uniquely opens its host). Mitigating it reduces the network's weighted critical-asset risk from 0.8911 to 0.8911 (-0.00%), measured via 4000 synchronized Monte Carlo trials.

---
