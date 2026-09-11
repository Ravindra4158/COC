import networkx as nx
import pandas as pd

from src.scoring.priority_score import score_all_vulnerabilities


def test_batch_scores_every_pair_and_preserves_ids():
    graph = nx.DiGraph([(0, 1), (1, 2)])
    graph.nodes[1]["vulnerabilities"] = ["v1", "v2"]
    vulnerabilities = pd.DataFrame([
        {"vuln_id": "v1", "host_id": 1, "cvss": 5, "exploit_probability": 0.5},
        {"vuln_id": "v2", "host_id": 1, "cvss": 6, "exploit_probability": 0.5},
    ])
    result = score_all_vulnerabilities(graph, vulnerabilities, [0, 1, 2], [0], {2: 1.0}, output_path=None)
    assert len(result) == 2
    assert set(result["vulnerability_id"]) == {"v1", "v2"}
    assert result["priority_score"].notna().all()
