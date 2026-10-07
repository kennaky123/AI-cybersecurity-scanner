from fastapi.testclient import TestClient

from backend.app.api.phishing import get_download_analyzer, get_sandbox_analyzer
from backend.app.main import app
from backend.app.services.browser_sandbox import BrowserSandboxAnalyzer, MockSandboxProvider, SandboxDownload
from backend.app.services.website_download_analyzer import MalwareScanResult, MockMalwareScanner, WebsiteDownloadAnalyzer


def test_observed_download_is_static_analyzed_and_malware_result_is_integrated() -> None:
    download = SandboxDownload(
        "https://example.com/payload.exe",
        "payload.exe",
        "application/octet-stream",
        4,
        "a" * 64,
        True,
        b"MZ!!",
    )
    sandbox = BrowserSandboxAnalyzer(MockSandboxProvider(downloads=[download]))
    analyzer = WebsiteDownloadAnalyzer(MockMalwareScanner(MalwareScanResult("completed", "MALWARE", 0.99, 99, "CRITICAL", ["Mock detector evidence"])))
    report = analyzer.analyze(sandbox.analyze("https://example.com"), website_risk="HIGH")

    assert report.website_risk == "HIGH"
    assert report.downloads[0].file["file_type"] == "PE_EXECUTABLE"
    assert report.downloads[0].malware_result.risk_level == "CRITICAL"
    assert "Website delivered a suspicious executable." in report.potential_impact
    assert report.downloads[0].file["execution_blocked"] is True


def test_no_completed_sandbox_means_no_confirmed_download() -> None:
    report = WebsiteDownloadAnalyzer().analyze(BrowserSandboxAnalyzer().analyze("https://example.com"))

    assert report.status == "unavailable"
    assert report.downloads == []
    assert not report.potential_impact


def test_download_analysis_api_uses_mock_sandbox_and_scanner() -> None:
    download = SandboxDownload("https://example.com/a.zip", "a.zip", "application/zip", 4, "b" * 64)
    sandbox = BrowserSandboxAnalyzer(MockSandboxProvider(downloads=[download]))
    analyzer = WebsiteDownloadAnalyzer(MockMalwareScanner(MalwareScanResult("completed", "BENIGN", 0.01, 1, "LOW", [])))
    app.dependency_overrides[get_sandbox_analyzer] = lambda: sandbox
    app.dependency_overrides[get_download_analyzer] = lambda: analyzer
    try:
        with TestClient(app) as client:
            response = client.post("/api/phishing/download-analysis", json={"url": "https://example.com"})
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json()["downloads"][0]["malware_result"]["prediction"] == "BENIGN"
