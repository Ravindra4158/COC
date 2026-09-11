import pandas as pd
import pytest

from src.data.loader import load_all_data, load_hosts
from src.data.validator import DataValidationError, validate_all


def test_valid_csv_loading():
    data = load_all_data("data/raw")
    validate_all(data)
    assert set(data) == {"hosts", "vulnerabilities", "network_edges", "critical_assets"}


def test_missing_file_handling(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_hosts(tmp_path / "hosts.csv")


def test_missing_column_handling(tmp_path):
    path = tmp_path / "hosts.csv"
    pd.DataFrame({"name": ["host"]}).to_csv(path, index=False)
    with pytest.raises(DataValidationError, match="missing required columns"):
        load_hosts(path)


def test_duplicate_and_invalid_vulnerability_values():
    data = load_all_data("data/raw")
    data["vulnerabilities"].loc[0, "vuln_id"] = data["vulnerabilities"].loc[1, "vuln_id"]
    with pytest.raises(DataValidationError, match="duplicate"):
        validate_all(data)

    data = load_all_data("data/raw")
    data["vulnerabilities"].loc[0, "cvss"] = 11
    with pytest.raises(DataValidationError, match="CVSS"):
        validate_all(data)

    data = load_all_data("data/raw")
    data["vulnerabilities"].loc[0, "exploit_probability"] = 2
    with pytest.raises(DataValidationError, match="exploit probabilities"):
        validate_all(data)


def test_invalid_host_references():
    data = load_all_data("data/raw")
    data["network_edges"].loc[0, "target"] = "missing-host"
    with pytest.raises(DataValidationError, match="network_edges.csv"):
        validate_all(data)