# Technical Explanations — Top-10 Patch Recommendations

**Baseline weighted critical-asset risk**: 11.2145  
**Simulation budget**: 4000 pre-drawn Monte Carlo trials (common-random-numbers variance reduction).  
**Vulnerabilities with measurable patch value**: 53 / 80

---

## 1. h39-v2 on host 39

| Metric | Value |
|--------|-------|
| CVSS | 8.4 |
| Exploit probability | 0.802 |
| Path | 0 → 29 → 39 |
| Risk reduction | 27.74% |
| Baseline → Patched risk | 11.2145 → 8.1040 |

h39-v2 on host 39 (CVSS 8.4, exploit prob 0.802) sits on attack path 0 → 29 → 39. Individual host-enablement contribution: 0.6692 (probability this vuln alone breaches its host). Patching it reduces the network's weighted critical-asset risk from 11.2145 to 8.1040 (−27.74%), measured via 4000 synchronized Monte Carlo trials.

---

## 2. h36-v1 on host 36

| Metric | Value |
|--------|-------|
| CVSS | 9.6 |
| Exploit probability | 0.949 |
| Path | 0 → 12 → 8 → 36 |
| Risk reduction | 9.61% |
| Baseline → Patched risk | 11.2145 → 10.1370 |

h36-v1 on host 36 (CVSS 9.6, exploit prob 0.949) sits on attack path 0 → 12 → 8 → 36. Individual host-enablement contribution: 0.5640 (probability this vuln alone breaches its host). Patching it reduces the network's weighted critical-asset risk from 11.2145 to 10.1370 (−9.61%), measured via 4000 synchronized Monte Carlo trials.

---

## 3. h38-v2 on host 38

| Metric | Value |
|--------|-------|
| CVSS | 7.6 |
| Exploit probability | 0.700 |
| Path | 0 → 12 → 35 → 38 → 37 → 29 → 39 |
| Risk reduction | 8.58% |
| Baseline → Patched risk | 11.2145 → 10.2528 |

h38-v2 on host 38 (CVSS 7.6, exploit prob 0.700) sits on attack path 0 → 12 → 35 → 38 → 37 → 29 → 39. Individual host-enablement contribution: 0.2474 (probability this vuln alone breaches its host). Patching it reduces the network's weighted critical-asset risk from 11.2145 to 10.2527 (−8.58%), measured via 4000 synchronized Monte Carlo trials.

---

## 4. h38-v1 on host 38

| Metric | Value |
|--------|-------|
| CVSS | 7.2 |
| Exploit probability | 0.647 |
| Path | 0 → 12 → 35 → 38 → 37 → 29 → 39 |
| Risk reduction | 7.22% |
| Baseline → Patched risk | 11.2145 → 10.4047 |

h38-v1 on host 38 (CVSS 7.2, exploit prob 0.647) sits on attack path 0 → 12 → 35 → 38 → 37 → 29 → 39. Individual host-enablement contribution: 0.1939 (probability this vuln alone breaches its host). Patching it reduces the network's weighted critical-asset risk from 11.2145 to 10.4047 (−7.22%), measured via 4000 synchronized Monte Carlo trials.

---

## 5. h26-v2 on host 26

| Metric | Value |
|--------|-------|
| CVSS | 9.0 |
| Exploit probability | 0.874 |
| Path | 0 → 29 → 26 → 25 → 22 → 11 → 7 → 39 |
| Risk reduction | 5.97% |
| Baseline → Patched risk | 11.2145 → 10.5445 |

h26-v2 on host 26 (CVSS 9.0, exploit prob 0.874) sits on attack path 0 → 29 → 26 → 25 → 22 → 11 → 7 → 39. Individual host-enablement contribution: 0.1152 (probability this vuln alone breaches its host). Patching it reduces the network's weighted critical-asset risk from 11.2145 to 10.5445 (−5.97%), measured via 4000 synchronized Monte Carlo trials.

---

## 6. h26-v1 on host 26

| Metric | Value |
|--------|-------|
| CVSS | 8.9 |
| Exploit probability | 0.868 |
| Path | 0 → 29 → 26 → 25 → 22 → 11 → 7 → 39 |
| Risk reduction | 5.66% |
| Baseline → Patched risk | 11.2145 → 10.5798 |

h26-v1 on host 26 (CVSS 8.9, exploit prob 0.868) sits on attack path 0 → 29 → 26 → 25 → 22 → 11 → 7 → 39. Individual host-enablement contribution: 0.1094 (probability this vuln alone breaches its host). Patching it reduces the network's weighted critical-asset risk from 11.2145 to 10.5797 (−5.66%), measured via 4000 synchronized Monte Carlo trials.

---

## 7. h29-v1 on host 29

| Metric | Value |
|--------|-------|
| CVSS | 8.0 |
| Exploit probability | 0.753 |
| Path | 0 → 29 → 39 |
| Risk reduction | 5.17% |
| Baseline → Patched risk | 11.2145 → 10.6348 |

h29-v1 on host 29 (CVSS 8.0, exploit prob 0.753) sits on attack path 0 → 29 → 39. Individual host-enablement contribution: 0.2983 (probability this vuln alone breaches its host). Patching it reduces the network's weighted critical-asset risk from 11.2145 to 10.6347 (−5.17%), measured via 4000 synchronized Monte Carlo trials.

---

## 8. h37-v1 on host 37

| Metric | Value |
|--------|-------|
| CVSS | 3.9 |
| Exploit probability | 0.238 |
| Path | 0 → 29 → 37 → 38 → 16 → 5 → 11 → 7 → 39 |
| Risk reduction | 4.99% |
| Baseline → Patched risk | 11.2145 → 10.6550 |

h37-v1 on host 37 (CVSS 3.9, exploit prob 0.238) sits on attack path 0 → 29 → 37 → 38 → 16 → 5 → 11 → 7 → 39. Individual host-enablement contribution: 0.1908 (probability this vuln alone breaches its host). Patching it reduces the network's weighted critical-asset risk from 11.2145 to 10.6550 (−4.99%), measured via 4000 synchronized Monte Carlo trials.

---

## 9. h8-v1 on host 8

| Metric | Value |
|--------|-------|
| CVSS | 9.0 |
| Exploit probability | 0.871 |
| Path | 0 → 12 → 8 → 14 → 15 → 37 → 29 → 39 |
| Risk reduction | 4.17% |
| Baseline → Patched risk | 11.2145 → 10.7465 |

h8-v1 on host 8 (CVSS 9.0, exploit prob 0.871) sits on attack path 0 → 12 → 8 → 14 → 15 → 37 → 29 → 39. Individual host-enablement contribution: 0.2450 (probability this vuln alone breaches its host). Patching it reduces the network's weighted critical-asset risk from 11.2145 to 10.7465 (−4.17%), measured via 4000 synchronized Monte Carlo trials.

---

## 10. h37-v2 on host 37

| Metric | Value |
|--------|-------|
| CVSS | 3.6 |
| Exploit probability | 0.199 |
| Path | 0 → 29 → 37 → 38 → 16 → 5 → 11 → 7 → 39 |
| Risk reduction | 3.96% |
| Baseline → Patched risk | 11.2145 → 10.7700 |

h37-v2 on host 37 (CVSS 3.6, exploit prob 0.199) sits on attack path 0 → 29 → 37 → 38 → 16 → 5 → 11 → 7 → 39. Individual host-enablement contribution: 0.1516 (probability this vuln alone breaches its host). Patching it reduces the network's weighted critical-asset risk from 11.2145 to 10.7700 (−3.96%), measured via 4000 synchronized Monte Carlo trials.

---
