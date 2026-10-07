from backend.app.api.phishing import get_sandbox_analyzer
from backend.app.main import app
from backend.app.services.browser_sandbox import (
    BrowserSandboxAnalyzer,
    MockSandboxProvider,
    SandboxDownload,
    TelemetryEvent,
    UnavailableSandboxProvider,
)
from fastapi.testclient import TestClient


def test_default_provider_is_unavailable_and_does_not_launch_host_browser() -> None:
    result = BrowserSandboxAnalyzer(UnavailableSandboxProvider()).analyze("https://example.com")

    assert result.status == "unavailable"
    assert result.telemetry == []
    assert any("No browser was launched" in item for item in result.explanation)


def test_mock_provider_collects_redirects_network_events_and_blocks_download_execution() -> None:
    provider = MockSandboxProvider(
        network=[
            TelemetryEvent("2026-01-01T00:00:00Z", "navigation", "https://example.com", "https://redirect.example/a", {"status_code": 302}),
            TelemetryEvent("2026-01-01T00:00:01Z", "redirect", "https://redirect.example/a", "https://final.example/login", {"status_code": 302}),
            TelemetryEvent("2026-01-01T00:00:02Z", "http_request", "https://final.example/login", "https://cdn.example/app.js", {"status_code": 200}),
        ],
        downloads=[SandboxDownload("https://final.example/payload.exe", "payload.exe", "application/octet-stream", 128, "a" * 64)],
    )
    result = BrowserSandboxAnalyzer(provider).analyze("https://example.com")

    assert result.status == "completed"
    assert len(result.redirect_chain) == 2
    assert "cdn.example" in result.external_domains
    assert result.downloads[0].execution_blocked is True
    assert provider.launched is True
    assert provider.shutdown_called is True


def test_provider_failure_still_shuts_down() -> None:
    provider = MockSandboxProvider(error=RuntimeError("mock provider failure"))
    result = BrowserSandboxAnalyzer(provider).analyze("https://example.com")

    assert result.status == "error"
    assert provider.shutdown_called is True


def test_sandbox_api_uses_mock_provider_without_real_browser() -> None:
    provider = MockSandboxProvider()
    app.dependency_overrides[get_sandbox_analyzer] = lambda: BrowserSandboxAnalyzer(provider)
    try:
        with TestClient(app) as client:
            response = client.post("/api/phishing/sandbox-analysis", json={"url": "https://example.com"})
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json()["status"] == "completed"
    assert provider.shutdown_called is True
