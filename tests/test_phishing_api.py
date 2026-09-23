from pathlib import Path

from fastapi.testclient import TestClient

from backend.app.api.phishing import get_phishing_detector
from backend.app.database import database
from backend.app.main import app
from backend.app.services.phishing_detector import PhishingAnalysis, PhishingDetector


class StubDetector:
    def analyze(self, url: str) -> PhishingAnalysis:
        return PhishingAnalysis(
            url=url,
            prediction="PHISHING",
            probability=0.94,
            risk_score=94,
            risk_level="CRITICAL",
            features={"url_length": len(url), "uses_https": 1},
            reasons=["url_length has high global model importance"],
        )


def test_analyze_returns_503_when_model_is_missing(tmp_path: Path) -> None:
    detector = PhishingDetector(
        model_path=tmp_path / "missing-model.joblib",
        preprocessor_path=tmp_path / "missing-preprocessor.joblib",
    )
    app.dependency_overrides[get_phishing_detector] = lambda: detector
    try:
        with TestClient(app) as client:
            response = client.post("/api/phishing/analyze", json={"url": "https://example.com"})
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 503
    assert response.json() == {"detail": "Phishing model unavailable. Train model first."}


def test_successful_analysis_is_saved_to_history(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "scanner.db")
    app.dependency_overrides[get_phishing_detector] = lambda: StubDetector()
    try:
        with TestClient(app) as client:
            response = client.post("/api/phishing/analyze", json={"url": "https://example.com"})
            history_response = client.get("/api/history")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    body = response.json()
    assert body["prediction"] == "PHISHING"
    assert body["url"] == "https://example.com"
    assert body["probability"] == 0.94
    assert body["risk_score"] == 94
    assert body["risk_level"] == "CRITICAL"
    assert body["explanation"]["method"] == "UNAVAILABLE"

    assert history_response.status_code == 200
    history = history_response.json()
    assert history["total"] == 1
    assert history["items"][0]["scan_type"] == "PHISHING"
    assert history["items"][0]["prediction"] == "PHISHING"
    assert history["items"][0]["probability"] == 0.94
    assert history["items"][0]["sha256"] is None
