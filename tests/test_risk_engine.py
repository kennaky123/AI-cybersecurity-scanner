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


def test_aggregate_report_separates_observed_model_and_threat_evidence() -> None:
    engine = RiskEngine()
    report = engine.assess(
        url_analysis={"score": 70, "features": {"contains_ip_address": 1}, "indicators": ["IP_BASED_URL"], "explanation": ["IP used"]},
        domain_analysis={"score": 75, "features": {}, "indicators": ["SUSPICIOUS_TLD"], "explanation": ["TLD review"]},
        html_analysis={"html_score": 80, "credential_fields": [{"type": "password"}], "external_submissions": [{"submission_domain": "evil.example"}], "indicators": ["EXTERNAL_FORM_SUBMISSION"], "explanation": ["External form"]},
        javascript_analysis={"javascript_score": 60, "observed_static_indicators": ["COOKIE_ACCESS"], "suspicious_behaviors": ["COOKIE_ACCESS_WITH_NETWORK_API"], "potential_capabilities": ["May read cookies"], "explanation": ["Static JS"]},
        threat_intelligence=[{"provider": "mock", "status": "found", "confidence": 0.9, "categories": ["phishing"], "evidence": ["listed"]}],
        model_probability=0.94,
    )

    assert report.classification == "PHISHING"
    assert report.risk_score >= 80
    assert {item.category for item in report.evidence} >= {"OBSERVED", "THREAT_INTELLIGENCE", "MODEL_PREDICTION"}
    assert any("cookies" in item.lower() for item in report.potential_impact)
    assert report.recommendations


def test_not_found_threat_intelligence_does_not_become_safe_evidence() -> None:
    report = RiskEngine().assess(
        url_analysis={"score": 0, "indicators": [], "explanation": []},
        domain_analysis={"score": 0, "indicators": [], "explanation": []},
        html_analysis={"html_score": 0, "indicators": [], "explanation": []},
        javascript_analysis={"javascript_score": 0, "indicators": [], "explanation": []},
        threat_intelligence=[{"provider": "mock", "status": "not_found", "confidence": 0, "categories": [], "evidence": []}],
        model_probability=0.01,
    )

    assert report.classification == "SAFE"
    assert not any(item.category == "THREAT_INTELLIGENCE" and item.observed_value == "not_found" for item in report.evidence)
    assert any("not a guarantee" in item.lower() for item in report.recommendations)
