from fastapi.testclient import TestClient

from backend.app.main import app

client = TestClient(app)


def test_get_all_metrics():
    response = client.get("/api/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "phishing" in data
    assert "malware" in data
    if data["phishing"]:
        assert data["phishing"]["model_type"] == "PHISHING"
        assert "test_metrics" in data["phishing"]
        assert "comparison" in data["phishing"]
        assert len(data["phishing"]["comparison"]) > 0
    if data["malware"]:
        assert data["malware"]["model_type"] == "MALWARE"
        assert "test_metrics" in data["malware"]
        assert "comparison" in data["malware"]


def test_get_phishing_metrics():
    response = client.get("/api/metrics/phishing")
    assert response.status_code == 200
    data = response.json()
    assert data["model_type"] == "PHISHING"
    assert data["selected_model"] == "LightGBM"
    assert data["test_metrics"]["accuracy"] > 0.9


def test_get_malware_metrics():
    response = client.get("/api/metrics/malware")
    assert response.status_code == 200
    data = response.json()
    assert data["model_type"] == "MALWARE"
    assert data["selected_model"] == "LightGBM"
    assert data["test_metrics"]["accuracy"] > 0.9
