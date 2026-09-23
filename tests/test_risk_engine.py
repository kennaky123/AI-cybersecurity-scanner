import pytest

from backend.app.services.risk_engine import RiskEngine


@pytest.mark.parametrize(
    ("probability", "score", "level"),
    [
        (0.00, 0, "LOW"),
        (0.29, 29, "LOW"),
        (0.30, 30, "MEDIUM"),
        (0.59, 59, "MEDIUM"),
        (0.60, 60, "HIGH"),
        (0.79, 79, "HIGH"),
        (0.80, 80, "CRITICAL"),
        (1.00, 100, "CRITICAL"),
    ],
)
def test_risk_boundaries(probability: float, score: int, level: str) -> None:
    risk = RiskEngine.calculate(probability)

    assert risk.score == score
    assert risk.level == level


@pytest.mark.parametrize("probability", [-0.01, 1.01])
def test_rejects_invalid_probability(probability: float) -> None:
    with pytest.raises(ValueError):
        RiskEngine.calculate(probability)
