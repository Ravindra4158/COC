# Technical Explanations — Top-10 Patch Recommendations

- **Baseline Weighted Critical-Asset Risk**: 14.6035
- **Monte Carlo Simulation Budget**: 3980 trials (within <= 4000 budget)
- **Total Vulnerabilities**: 80
- **Execution Runtime**: 0.27s

---

## #1. h39-v2 on Host 39

| Metric | Value |
|---|---|
| CVSS Severity | 8.4 |
| Exploit Probability | 0.802 |
| Verified Attack Path | `0 → 29 → 39 → 7 → 11 → 5 → 35` |
| Estimated Risk Reduction | **30.42%** (fraction: 0.3042) |
| Network Risk Impact | 11.4545 → 7.9697 |

> **Rationale**: h39-v2 on host 39 (CVSS 8.4, exploit prob 0.802) lies on attack path 0 → 29 → 39 → 7 → 11 → 5 → 35. Marginal host-compromise enablement: 0.6692 (probability this vulnerability uniquely opens the host). Acts as a bottleneck node traversing 2 attack path(s). Threatens downstream critical assets: [35, 36, 37, 38, 39]. Mitigating it reduces network weighted critical-asset risk from 11.4545 to 7.9697 (-30.4%).

---

## #2. h38-v1 on Host 38

| Metric | Value |
|---|---|
| CVSS Severity | 7.2 |
| Exploit Probability | 0.647 |
| Verified Attack Path | `0 → 12 → 35 → 38 → 37 → 15 → 14 → 8 → 36` |
| Estimated Risk Reduction | **10.05%** (fraction: 0.1005) |
| Network Risk Impact | 11.4545 → 10.3030 |

> **Rationale**: h38-v1 on host 38 (CVSS 7.2, exploit prob 0.647) lies on attack path 0 → 12 → 35 → 38 → 37 → 15 → 14 → 8 → 36. Marginal host-compromise enablement: 0.1939 (probability this vulnerability uniquely opens the host). Acts as a bottleneck node traversing 2 attack path(s). Threatens downstream critical assets: [35, 36, 37, 38, 39]. Mitigating it reduces network weighted critical-asset risk from 11.4545 to 10.3030 (-10.1%).

---

## #3. h36-v1 on Host 36

| Metric | Value |
|---|---|
| CVSS Severity | 9.6 |
| Exploit Probability | 0.949 |
| Verified Attack Path | `0 → 12 → 8 → 36` |
| Estimated Risk Reduction | **9.26%** (fraction: 0.0926) |
| Network Risk Impact | 11.4545 → 10.3939 |

> **Rationale**: h36-v1 on host 36 (CVSS 9.6, exploit prob 0.949) lies on attack path 0 → 12 → 8 → 36. Marginal host-compromise enablement: 0.5640 (probability this vulnerability uniquely opens the host). Acts as a bottleneck node traversing 2 attack path(s). Threatens downstream critical assets: [35, 36, 37, 38, 39]. Mitigating it reduces network weighted critical-asset risk from 11.4545 to 10.3939 (-9.3%).

---

## #4. h38-v2 on Host 38

| Metric | Value |
|---|---|
| CVSS Severity | 7.6 |
| Exploit Probability | 0.700 |
| Verified Attack Path | `0 → 12 → 35 → 38 → 37 → 15 → 14 → 8 → 36` |
| Estimated Risk Reduction | **4.63%** (fraction: 0.0463) |
| Network Risk Impact | 11.4545 → 10.9242 |

> **Rationale**: h38-v2 on host 38 (CVSS 7.6, exploit prob 0.700) lies on attack path 0 → 12 → 35 → 38 → 37 → 15 → 14 → 8 → 36. Marginal host-compromise enablement: 0.2474 (probability this vulnerability uniquely opens the host). Acts as a bottleneck node traversing 2 attack path(s). Threatens downstream critical assets: [35, 36, 37, 38, 39]. Mitigating it reduces network weighted critical-asset risk from 11.4545 to 10.9242 (-4.6%).

---

## #5. h8-v1 on Host 8

| Metric | Value |
|---|---|
| CVSS Severity | 9.0 |
| Exploit Probability | 0.871 |
| Verified Attack Path | `0 → 12 → 8 → 14 → 13 → 5 → 35` |
| Estimated Risk Reduction | **4.23%** (fraction: 0.0423) |
| Network Risk Impact | 11.4545 → 10.9697 |

> **Rationale**: h8-v1 on host 8 (CVSS 9.0, exploit prob 0.871) lies on attack path 0 → 12 → 8 → 14 → 13 → 5 → 35. Marginal host-compromise enablement: 0.2450 (probability this vulnerability uniquely opens the host). Acts as a bottleneck node traversing 2 attack path(s). Threatens downstream critical assets: [35, 36, 37, 38, 39]. Mitigating it reduces network weighted critical-asset risk from 11.4545 to 10.9697 (-4.2%).

---

## #6. h29-v2 on Host 29

| Metric | Value |
|---|---|
| CVSS Severity | 6.8 |
| Exploit Probability | 0.604 |
| Verified Attack Path | `0 → 29 → 37 → 38 → 35` |
| Estimated Risk Reduction | **3.97%** (fraction: 0.0397) |
| Network Risk Impact | 11.4545 → 11.0000 |

> **Rationale**: h29-v2 on host 29 (CVSS 6.8, exploit prob 0.604) lies on attack path 0 → 29 → 37 → 38 → 35. Marginal host-compromise enablement: 0.1490 (probability this vulnerability uniquely opens the host). Acts as a bottleneck node traversing 5 attack path(s). Threatens downstream critical assets: [35, 36, 37, 38, 39]. Mitigating it reduces network weighted critical-asset risk from 11.4545 to 11.0000 (-4.0%).

---

## #7. h26-v1 on Host 26

| Metric | Value |
|---|---|
| CVSS Severity | 8.9 |
| Exploit Probability | 0.868 |
| Verified Attack Path | `0 → 29 → 26 → 25 → 10 → 35` |
| Estimated Risk Reduction | **3.70%** (fraction: 0.0370) |
| Network Risk Impact | 11.4545 → 11.0303 |

> **Rationale**: h26-v1 on host 26 (CVSS 8.9, exploit prob 0.868) lies on attack path 0 → 29 → 26 → 25 → 10 → 35. Marginal host-compromise enablement: 0.1094 (probability this vulnerability uniquely opens the host). Acts as a bottleneck node traversing 5 attack path(s). Threatens downstream critical assets: [35, 36, 37, 38, 39]. Mitigating it reduces network weighted critical-asset risk from 11.4545 to 11.0303 (-3.7%).

---

## #8. h26-v2 on Host 26

| Metric | Value |
|---|---|
| CVSS Severity | 9.0 |
| Exploit Probability | 0.874 |
| Verified Attack Path | `0 → 29 → 26 → 25 → 10 → 35` |
| Estimated Risk Reduction | **2.78%** (fraction: 0.0278) |
| Network Risk Impact | 11.4545 → 11.1364 |

> **Rationale**: h26-v2 on host 26 (CVSS 9.0, exploit prob 0.874) lies on attack path 0 → 29 → 26 → 25 → 10 → 35. Marginal host-compromise enablement: 0.1152 (probability this vulnerability uniquely opens the host). Acts as a bottleneck node traversing 5 attack path(s). Threatens downstream critical assets: [35, 36, 37, 38, 39]. Mitigating it reduces network weighted critical-asset risk from 11.4545 to 11.1364 (-2.8%).

---

## #9. h29-v1 on Host 29

| Metric | Value |
|---|---|
| CVSS Severity | 8.0 |
| Exploit Probability | 0.753 |
| Verified Attack Path | `0 → 29 → 37 → 38 → 35` |
| Estimated Risk Reduction | **2.65%** (fraction: 0.0265) |
| Network Risk Impact | 11.4545 → 11.1515 |

> **Rationale**: h29-v1 on host 29 (CVSS 8.0, exploit prob 0.753) lies on attack path 0 → 29 → 37 → 38 → 35. Marginal host-compromise enablement: 0.2983 (probability this vulnerability uniquely opens the host). Acts as a bottleneck node traversing 5 attack path(s). Threatens downstream critical assets: [35, 36, 37, 38, 39]. Mitigating it reduces network weighted critical-asset risk from 11.4545 to 11.1515 (-2.6%).

---

## #10. h35-v1 on Host 35

| Metric | Value |
|---|---|
| CVSS Severity | 6.8 |
| Exploit Probability | 0.596 |
| Verified Attack Path | `0 → 12 → 35` |
| Estimated Risk Reduction | **2.12%** (fraction: 0.0212) |
| Network Risk Impact | 11.4545 → 11.2121 |

> **Rationale**: h35-v1 on host 35 (CVSS 6.8, exploit prob 0.596) lies on attack path 0 → 12 → 35. Marginal host-compromise enablement: 0.2680 (probability this vulnerability uniquely opens the host). Acts as a bottleneck node traversing 3 attack path(s). Threatens downstream critical assets: [35, 36, 37, 38, 39]. Mitigating it reduces network weighted critical-asset risk from 11.4545 to 11.2121 (-2.1%).

---
