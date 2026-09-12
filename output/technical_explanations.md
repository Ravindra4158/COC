# Technical Explanations — Top-10 Patch Recommendations

- **Baseline Weighted Critical-Asset Risk**: 12.7070
- **Monte Carlo Simulation Budget**: 3980 trials (within <= 4000 budget)
- **Total Vulnerabilities**: 80
- **Execution Runtime**: 2.31s

---

## #1. h38-v1 on Host 38

| Metric | Value |
|---|---|
| CVSS Severity | 7.2 |
| Exploit Probability | 0.647 |
| Verified Attack Path | `0 → 12 → 35 → 38 → 37 → 15 → 14 → 8 → 36` |
| Estimated Risk Reduction | **14.45%** (fraction: 0.1445) |
| Network Risk Impact | 7.9697 → 6.8182 |

> **Rationale**: h38-v1 on host 38 (CVSS 7.2, exploit prob 0.647) lies on attack path 0 → 12 → 35 → 38 → 37 → 15 → 14 → 8 → 36. Marginal host-compromise enablement: 0.1939 (probability this vulnerability uniquely opens the host). Acts as a bottleneck node traversing 2 attack path(s). Threatens downstream critical assets: [35, 36, 37, 38, 39]. Mitigating it reduces network weighted critical-asset risk from 7.9697 to 6.8182 (-14.4%).

---

## #2. h36-v1 on Host 36

| Metric | Value |
|---|---|
| CVSS Severity | 9.6 |
| Exploit Probability | 0.949 |
| Verified Attack Path | `0 → 12 → 8 → 36` |
| Estimated Risk Reduction | **13.31%** (fraction: 0.1331) |
| Network Risk Impact | 7.9697 → 6.9091 |

> **Rationale**: h36-v1 on host 36 (CVSS 9.6, exploit prob 0.949) lies on attack path 0 → 12 → 8 → 36. Marginal host-compromise enablement: 0.5640 (probability this vulnerability uniquely opens the host). Acts as a bottleneck node traversing 2 attack path(s). Threatens downstream critical assets: [35, 36, 37, 38, 39]. Mitigating it reduces network weighted critical-asset risk from 7.9697 to 6.9091 (-13.3%).

---

## #3. h38-v2 on Host 38

| Metric | Value |
|---|---|
| CVSS Severity | 7.6 |
| Exploit Probability | 0.700 |
| Verified Attack Path | `0 → 12 → 35 → 38 → 37 → 15 → 14 → 8 → 36` |
| Estimated Risk Reduction | **6.65%** (fraction: 0.0665) |
| Network Risk Impact | 7.9697 → 7.4394 |

> **Rationale**: h38-v2 on host 38 (CVSS 7.6, exploit prob 0.700) lies on attack path 0 → 12 → 35 → 38 → 37 → 15 → 14 → 8 → 36. Marginal host-compromise enablement: 0.2474 (probability this vulnerability uniquely opens the host). Acts as a bottleneck node traversing 2 attack path(s). Threatens downstream critical assets: [35, 36, 37, 38, 39]. Mitigating it reduces network weighted critical-asset risk from 7.9697 to 7.4394 (-6.7%).

---

## #4. h8-v1 on Host 8

| Metric | Value |
|---|---|
| CVSS Severity | 9.0 |
| Exploit Probability | 0.871 |
| Verified Attack Path | `0 → 12 → 8 → 14 → 13 → 5 → 35` |
| Estimated Risk Reduction | **6.08%** (fraction: 0.0608) |
| Network Risk Impact | 7.9697 → 7.4848 |

> **Rationale**: h8-v1 on host 8 (CVSS 9.0, exploit prob 0.871) lies on attack path 0 → 12 → 8 → 14 → 13 → 5 → 35. Marginal host-compromise enablement: 0.2450 (probability this vulnerability uniquely opens the host). Acts as a bottleneck node traversing 2 attack path(s). Threatens downstream critical assets: [35, 36, 37, 38, 39]. Mitigating it reduces network weighted critical-asset risk from 7.9697 to 7.4848 (-6.1%).

---

## #5. h26-v1 on Host 26

| Metric | Value |
|---|---|
| CVSS Severity | 8.9 |
| Exploit Probability | 0.868 |
| Verified Attack Path | `0 → 29 → 26 → 25 → 10 → 35` |
| Estimated Risk Reduction | **3.42%** (fraction: 0.0342) |
| Network Risk Impact | 7.9697 → 7.6970 |

> **Rationale**: h26-v1 on host 26 (CVSS 8.9, exploit prob 0.868) lies on attack path 0 → 29 → 26 → 25 → 10 → 35. Marginal host-compromise enablement: 0.1094 (probability this vulnerability uniquely opens the host). Acts as a bottleneck node traversing 5 attack path(s). Threatens downstream critical assets: [35, 36, 37, 38, 39]. Mitigating it reduces network weighted critical-asset risk from 7.9697 to 7.6970 (-3.4%).

---

## #6. h26-v2 on Host 26

| Metric | Value |
|---|---|
| CVSS Severity | 9.0 |
| Exploit Probability | 0.874 |
| Verified Attack Path | `0 → 29 → 26 → 25 → 10 → 35` |
| Estimated Risk Reduction | **3.04%** (fraction: 0.0304) |
| Network Risk Impact | 7.9697 → 7.7273 |

> **Rationale**: h26-v2 on host 26 (CVSS 9.0, exploit prob 0.874) lies on attack path 0 → 29 → 26 → 25 → 10 → 35. Marginal host-compromise enablement: 0.1152 (probability this vulnerability uniquely opens the host). Acts as a bottleneck node traversing 5 attack path(s). Threatens downstream critical assets: [35, 36, 37, 38, 39]. Mitigating it reduces network weighted critical-asset risk from 7.9697 to 7.7273 (-3.0%).

---

## #7. h35-v1 on Host 35

| Metric | Value |
|---|---|
| CVSS Severity | 6.8 |
| Exploit Probability | 0.596 |
| Verified Attack Path | `0 → 12 → 35` |
| Estimated Risk Reduction | **3.04%** (fraction: 0.0304) |
| Network Risk Impact | 7.9697 → 7.7273 |

> **Rationale**: h35-v1 on host 35 (CVSS 6.8, exploit prob 0.596) lies on attack path 0 → 12 → 35. Marginal host-compromise enablement: 0.2680 (probability this vulnerability uniquely opens the host). Acts as a bottleneck node traversing 3 attack path(s). Threatens downstream critical assets: [35, 36, 37, 38, 39]. Mitigating it reduces network weighted critical-asset risk from 7.9697 to 7.7273 (-3.0%).

---

## #8. h35-v2 on Host 35

| Metric | Value |
|---|---|
| CVSS Severity | 6.4 |
| Exploit Probability | 0.551 |
| Verified Attack Path | `0 → 12 → 35` |
| Estimated Risk Reduction | **3.04%** (fraction: 0.0304) |
| Network Risk Impact | 7.9697 → 7.7273 |

> **Rationale**: h35-v2 on host 35 (CVSS 6.4, exploit prob 0.551) lies on attack path 0 → 12 → 35. Marginal host-compromise enablement: 0.2222 (probability this vulnerability uniquely opens the host). Acts as a bottleneck node traversing 3 attack path(s). Threatens downstream critical assets: [35, 36, 37, 38, 39]. Mitigating it reduces network weighted critical-asset risk from 7.9697 to 7.7273 (-3.0%).

---

## #9. h29-v2 on Host 29

| Metric | Value |
|---|---|
| CVSS Severity | 6.8 |
| Exploit Probability | 0.604 |
| Verified Attack Path | `0 → 29 → 37 → 38 → 35` |
| Estimated Risk Reduction | **1.90%** (fraction: 0.0190) |
| Network Risk Impact | 7.9697 → 7.8182 |

> **Rationale**: h29-v2 on host 29 (CVSS 6.8, exploit prob 0.604) lies on attack path 0 → 29 → 37 → 38 → 35. Marginal host-compromise enablement: 0.1490 (probability this vulnerability uniquely opens the host). Acts as a bottleneck node traversing 5 attack path(s). Threatens downstream critical assets: [35, 36, 37, 38, 39]. Mitigating it reduces network weighted critical-asset risk from 7.9697 to 7.8182 (-1.9%).

---

## #10. h8-v2 on Host 8

| Metric | Value |
|---|---|
| CVSS Severity | 7.8 |
| Exploit Probability | 0.719 |
| Verified Attack Path | `0 → 12 → 8 → 14 → 13 → 5 → 35` |
| Estimated Risk Reduction | **1.90%** (fraction: 0.0190) |
| Network Risk Impact | 7.9697 → 7.8182 |

> **Rationale**: h8-v2 on host 8 (CVSS 7.8, exploit prob 0.719) lies on attack path 0 → 12 → 8 → 14 → 13 → 5 → 35. Marginal host-compromise enablement: 0.0926 (probability this vulnerability uniquely opens the host). Acts as a bottleneck node traversing 2 attack path(s). Threatens downstream critical assets: [35, 36, 37, 38, 39]. Mitigating it reduces network weighted critical-asset risk from 7.9697 to 7.8182 (-1.9%).

---
