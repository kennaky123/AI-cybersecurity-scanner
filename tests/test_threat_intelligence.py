import httpx
from fastapi.testclient import TestClient

from backend.app.api.threat_intelligence import get_threat_intel_manager
from backend.app.main import app
from backend.app.services.threat_intelligence import (
    GoogleSafeBrowsingProvider,
    OpenPhishProvider,
    PhishTankProvider,
    ThreatIntelManager,
    ThreatIntelResult,
    VirusTotalProvider,
)


def responder(status: int, payload: dict):
    def request(*args, **kwargs):
        return httpx.Response(status, json=payload)
    return request


def test_unconfigured_provider_is_unavailable() -> None:
    result = VirusTotalProvider().lookup("URL", "https://example.com")

    assert result.status == "unavailable"
    assert result.confidence == 0


def test_phishtank_found_is_normalized() -> None:
    provider = PhishTankProvider("test-key", requester=responder(200, {"results": {"in_database": True, "valid": True, "verified": True, "verified_at": "2026-01-01T00:00:00Z"}}))
    result = provider.lookup("URL", "https://bad.example/login")

    assert result.status == "found"
    assert result.categories == ["phishing"]
    assert result.confidence == 0.95


def test_openphish_not_found_is_not_safe() -> None:
    provider = OpenPhishProvider("https://mock.openphish/check", requester=responder(200, {"found": False}))
    result = provider.lookup("URL", "https://example.com")

    assert result.status == "not_found"
    assert result.evidence


def test_google_match_and_virustotal_rate_limit() -> None:
    google = GoogleSafeBrowsingProvider("test-key", requester=responder(200, {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]}))
    vt = VirusTotalProvider("test-key", requester=responder(429, {}))

    assert google.lookup("URL", "https://bad.example").status == "found"
    assert vt.lookup("FILE_HASH", "a" * 64).status == "error"
    assert "rate limit" in vt.lookup("FILE_HASH", "a" * 64).evidence[0].lower()


def test_manager_isolates_provider_failures() -> None:
    class BrokenProvider:
        name = "broken"

        def lookup(self, indicator_type, value):
            raise RuntimeError("provider down")

    manager = ThreatIntelManager([BrokenProvider(), VirusTotalProvider()])
    results = manager.lookup("DOMAIN", "example.com")

    assert [result.status for result in results] == ["error", "unavailable"]


def test_threat_intelligence_api_returns_provider_results() -> None:
    manager = ThreatIntelManager([VirusTotalProvider()])
    app.dependency_overrides[get_threat_intel_manager] = lambda: manager
    try:
        with TestClient(app) as client:
            response = client.post("/api/threat-intelligence/lookup", json={"indicator_type": "IP", "value": "1.1.1.1"})
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json()["results"][0]["status"] == "unavailable"
