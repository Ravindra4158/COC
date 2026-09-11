import networkx as nx

from src.scoring.asset_impact import calculate_asset_impact


def test_asset_impact_tracks_multiple_assets():
    graph = nx.DiGraph([("host", "asset-1"), ("host", "asset-2")])
    exposure_one, _ = calculate_asset_impact(graph, "host", {"asset-1": 1.0}, ["asset-1"], 1)
    exposure_two, criticality = calculate_asset_impact(graph, "host", {"asset-1": 1.0, "asset-2": 0.5}, ["asset-1", "asset-2"], 1)
    assert exposure_one > 0
    assert exposure_two >= exposure_one
    assert criticality == 1.0


def test_disconnected_host_has_no_asset_impact():
    graph = nx.DiGraph([("host", "asset")])
    assert calculate_asset_impact(graph, "isolated", {"asset": 1.0}, [], None)[0] == 0.0
