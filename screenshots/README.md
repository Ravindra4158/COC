# Screenshot Directory & Asset Guide

This directory holds visual assets and screenshots referenced in the main project [`README.md`](../README.md).

## Recommended Screenshots to Place Here

| File Name | Description | Key Elements to Showcase |
|:---|:---|:---|
| `01_network_graph_cytoscape.png` | **Interactive Network Topology Graph** | Entry points (green hosts 0, 1), Critical assets (crimson hosts 35-39), choke points, and animated attack propagation paths in Cytoscape.js. |
| `02_vulnerability_ranking_table.png` | **Prioritized Vulnerability Matrix** | Table showing CVSS vs. Graph-Aware Priority Score (0–100), marginal enablement ($\Delta P_{\text{comp}}$), downstream exposure, and path witness tags. |
| `03_patch_impact_roi.png` | **Counterfactual Patch Impact Chart** | Waterfall and bar charts depicting simulated $\Delta R(v)$ risk reduction across candidates under Common Random Numbers (CRN). |
| `04_defense_cascade_100_percent.png` | **Defense Cascade to 100% Security** | Step-by-step sequential remediation curve showing risk drops: Host 39 (-49.5%) → Host 20 (-79.8%) → Host 18 (-100.0% / 100% SECURE). |
| `05_attack_path_investigation.png` | **Forensic Attack Path Witness Drawer** | Node detail drawer showing causal chain `0 → 29 → 39 → 7 → 11 → 5 → 35`, sibling vulnerability dilution, and technical remediation rationale. |

## Screenshot Guidelines
- **Resolution**: 1920x1080 (1080p) or 2560x1440 (1440p)
- **Theme**: Dark mode (Enterprise SIEM theme)
- **Format**: PNG with lossless compression
