import pytest

from src.simulation.budget import (
    DEFAULT_SIMULATIONS,
    EXPLORATORY_SIMULATIONS,
    MAX_SIMULATIONS,
    get_simulation_budget,
    validate_simulation_budget,
)


def test_simulation_budget_is_bounded():
    assert get_simulation_budget(100) == 100
    assert get_simulation_budget(4000) == MAX_SIMULATIONS
    assert get_simulation_budget(5000) == MAX_SIMULATIONS
    assert get_simulation_budget(confidence="exploratory") == EXPLORATORY_SIMULATIONS
    assert get_simulation_budget() == DEFAULT_SIMULATIONS


def test_invalid_simulation_budget():
    with pytest.raises(ValueError):
        validate_simulation_budget(0)
    with pytest.raises(ValueError):
        validate_simulation_budget(-1)
    with pytest.raises(ValueError):
        get_simulation_budget(confidence="unknown")
