# Technical Explanations — Top-10 Patch Recommendations

- **Baseline Weighted Critical-Asset Risk**: 11.2145
- **Monte Carlo Simulation Budget**: 4000 synchronized trials (within <= 4000 budget)
- **Measurable Patch Findings**: 53 / 80
- **Execution Runtime**: 0.88s

---

## #1. h39-v2 on Host 39

| Metric | Value |
|---|---|
| CVSS Severity | 8.4 |
| Exploit Probability | 0.802 |
| Verified Attack Path | `0 → 29 → 39` |
| Estimated Risk Reduction | **27.74%** (fraction: 0.2774) |
| Network Risk Impact | 11.2145 → 8.1040 |

> **Rationale**: h39-v2 on host 39 (CVSS 8.4, exploit prob 0.802) sits on attack path 0 → 29 → 39. Marginal host enablement: 0.6692 (probability this vulnerability uniquely opens its host). Mitigating it reduces the network's weighted critical-asset risk from 11.2145 to 8.1040 (-27.74%), measured via 4000 synchronized Monte Carlo trials.

---

## #2. h36-v1 on Host 36

| Metric | Value |
|---|---|
| CVSS Severity | 9.6 |
| Exploit Probability | 0.949 |
| Verified Attack Path | `0 → 12 → 8 → 36` |
| Estimated Risk Reduction | **9.61%** (fraction: 0.0961) |
| Network Risk Impact | 11.2145 → 10.1370 |

> **Rationale**: h36-v1 on host 36 (CVSS 9.6, exploit prob 0.949) sits on attack path 0 → 12 → 8 → 36. Marginal host enablement: 0.5640 (probability this vulnerability uniquely opens its host). Mitigating it reduces the network's weighted critical-asset risk from 11.2145 to 10.1370 (-9.61%), measured via 4000 synchronized Monte Carlo trials.

---

## #3. h38-v2 on Host 38

| Metric | Value |
|---|---|
| CVSS Severity | 7.6 |
| Exploit Probability | 0.700 |
| Verified Attack Path | `0 → 12 → 35 → 38 → 37 → 29 → 39` |
| Estimated Risk Reduction | **8.58%** (fraction: 0.0858) |
| Network Risk Impact | 11.2145 → 10.2528 |

> **Rationale**: h38-v2 on host 38 (CVSS 7.6, exploit prob 0.700) sits on attack path 0 → 12 → 35 → 38 → 37 → 29 → 39. Marginal host enablement: 0.2474 (probability this vulnerability uniquely opens its host). Mitigating it reduces the network's weighted critical-asset risk from 11.2145 to 10.2527 (-8.58%), measured via 4000 synchronized Monte Carlo trials.

---

## #4. h38-v1 on Host 38

| Metric | Value |
|---|---|
| CVSS Severity | 7.2 |
| Exploit Probability | 0.647 |
| Verified Attack Path | `0 → 12 → 35 → 38 → 37 → 29 → 39` |
| Estimated Risk Reduction | **7.22%** (fraction: 0.0722) |
| Network Risk Impact | 11.2145 → 10.4047 |

> **Rationale**: h38-v1 on host 38 (CVSS 7.2, exploit prob 0.647) sits on attack path 0 → 12 → 35 → 38 → 37 → 29 → 39. Marginal host enablement: 0.1939 (probability this vulnerability uniquely opens its host). Mitigating it reduces the network's weighted critical-asset risk from 11.2145 to 10.4047 (-7.22%), measured via 4000 synchronized Monte Carlo trials.

---

## #5. h26-v2 on Host 26

| Metric | Value |
|---|---|
| CVSS Severity | 9.0 |
| Exploit Probability | 0.874 |
| Verified Attack Path | `0 → 29 → 26 → 25 → 22 → 11 → 7 → 39` |
| Estimated Risk Reduction | **5.97%** (fraction: 0.0597) |
| Network Risk Impact | 11.2145 → 10.5445 |

> **Rationale**: h26-v2 on host 26 (CVSS 9.0, exploit prob 0.874) sits on attack path 0 → 29 → 26 → 25 → 22 → 11 → 7 → 39. Marginal host enablement: 0.1152 (probability this vulnerability uniquely opens its host). Mitigating it reduces the network's weighted critical-asset risk from 11.2145 to 10.5445 (-5.97%), measured via 4000 synchronized Monte Carlo trials.

---

## #6. h26-v1 on Host 26

| Metric | Value |
|---|---|
| CVSS Severity | 8.9 |
| Exploit Probability | 0.868 |
| Verified Attack Path | `0 → 29 → 26 → 25 → 22 → 11 → 7 → 39` |
| Estimated Risk Reduction | **5.66%** (fraction: 0.0566) |
| Network Risk Impact | 11.2145 → 10.5798 |

> **Rationale**: h26-v1 on host 26 (CVSS 8.9, exploit prob 0.868) sits on attack path 0 → 29 → 26 → 25 → 22 → 11 → 7 → 39. Marginal host enablement: 0.1094 (probability this vulnerability uniquely opens its host). Mitigating it reduces the network's weighted critical-asset risk from 11.2145 to 10.5797 (-5.66%), measured via 4000 synchronized Monte Carlo trials.

---

## #7. h29-v1 on Host 29

| Metric | Value |
|---|---|
| CVSS Severity | 8.0 |
| Exploit Probability | 0.753 |
| Verified Attack Path | `0 → 29 → 39` |
| Estimated Risk Reduction | **5.17%** (fraction: 0.0517) |
| Network Risk Impact | 11.2145 → 10.6348 |

> **Rationale**: h29-v1 on host 29 (CVSS 8.0, exploit prob 0.753) sits on attack path 0 → 29 → 39. Marginal host enablement: 0.2983 (probability this vulnerability uniquely opens its host). Mitigating it reduces the network's weighted critical-asset risk from 11.2145 to 10.6347 (-5.17%), measured via 4000 synchronized Monte Carlo trials.

---

## #8. h37-v1 on Host 37

| Metric | Value |
|---|---|
| CVSS Severity | 3.9 |
| Exploit Probability | 0.238 |
| Verified Attack Path | `0 → 29 → 37 → 38 → 16 → 5 → 11 → 7 → 39` |
| Estimated Risk Reduction | **4.99%** (fraction: 0.0499) |
| Network Risk Impact | 11.2145 → 10.6550 |

> **Rationale**: h37-v1 on host 37 (CVSS 3.9, exploit prob 0.238) sits on attack path 0 → 29 → 37 → 38 → 16 → 5 → 11 → 7 → 39. Marginal host enablement: 0.1908 (probability this vulnerability uniquely opens its host). Mitigating it reduces the network's weighted critical-asset risk from 11.2145 to 10.6550 (-4.99%), measured via 4000 synchronized Monte Carlo trials.

---

## #9. h8-v1 on Host 8

| Metric | Value |
|---|---|
| CVSS Severity | 9.0 |
| Exploit Probability | 0.871 |
| Verified Attack Path | `0 → 12 → 8 → 14 → 15 → 37 → 29 → 39` |
| Estimated Risk Reduction | **4.17%** (fraction: 0.0417) |
| Network Risk Impact | 11.2145 → 10.7465 |

> **Rationale**: h8-v1 on host 8 (CVSS 9.0, exploit prob 0.871) sits on attack path 0 → 12 → 8 → 14 → 15 → 37 → 29 → 39. Marginal host enablement: 0.2450 (probability this vulnerability uniquely opens its host). Mitigating it reduces the network's weighted critical-asset risk from 11.2145 to 10.7465 (-4.17%), measured via 4000 synchronized Monte Carlo trials.

---

## #10. h37-v2 on Host 37

| Metric | Value |
|---|---|
| CVSS Severity | 3.6 |
| Exploit Probability | 0.199 |
| Verified Attack Path | `0 → 29 → 37 → 38 → 16 → 5 → 11 → 7 → 39` |
| Estimated Risk Reduction | **3.96%** (fraction: 0.0396) |
| Network Risk Impact | 11.2145 → 10.7700 |

> **Rationale**: h37-v2 on host 37 (CVSS 3.6, exploit prob 0.199) sits on attack path 0 → 29 → 37 → 38 → 16 → 5 → 11 → 7 → 39. Marginal host enablement: 0.1516 (probability this vulnerability uniquely opens its host). Mitigating it reduces the network's weighted critical-asset risk from 11.2145 to 10.7700 (-3.96%), measured via 4000 synchronized Monte Carlo trials.

---
