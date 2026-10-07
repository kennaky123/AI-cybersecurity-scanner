from fastapi.testclient import TestClient

from backend.app.api.phishing import get_sandbox_analyzer, get_visual_analyzer
from backend.app.main import app
from backend.app.services.browser_sandbox import BrowserSandboxAnalyzer, MockSandboxProvider, ScreenshotArtifact
from backend.app.services.visual_analyzer import MockVisionProvider, VisualAnalyzer


def test_mock_visual_provider_detects_brand_impersonation_with_context() -> None:
    screenshot = ScreenshotArtifact.from_bytes("https://paypal-login-example.xyz", b"safe-mock-image")
    visual = VisualAnalyzer(MockVisionProvider({
        "detected_brand": "PayPal",
        "logo_detected": True,
        "ocr_text": ["PayPal", "Log in"],
        "login_page_detected": True,
        "visual_similarity": 0.91,
        "layout_similarity": 0.88,
    }))
    result = visual.analyze(
        screenshot,
        page_url=screenshot.url,
        domain_analysis={"indicators": ["SUSPICIOUS_TLD"]},
        html_analysis={"indicators": ["PASSWORD_FIELD_PRESENT"]},
        threat_intelligence=[],
    )

    assert result.status == "completed"
    assert result.detected_brand == "PayPal"
    assert result.visual_similarity == 0.91
    assert result.domain_matches_brand is False
    assert result.brand_impersonation is True
    assert any(item.indicator == "BRAND_DOMAIN_MISMATCH" for item in result.evidence)
    assert any("not a phishing verdict" in item for item in result.explanation)


def test_visual_similarity_alone_does_not_create_brand_impersonation() -> None:
    screenshot = ScreenshotArtifact.from_bytes("https://paypal.com/login", b"safe-mock-image")
    visual = VisualAnalyzer(MockVisionProvider({"detected_brand": "PayPal", "visual_similarity": 0.95}))
    result = visual.analyze(screenshot, page_url=screenshot.url)

    assert result.domain_matches_brand is True
    assert result.brand_impersonation is False


def test_visual_api_is_unavailable_without_sandbox_screenshot() -> None:
    app.dependency_overrides[get_sandbox_analyzer] = lambda: BrowserSandboxAnalyzer()
    app.dependency_overrides[get_visual_analyzer] = lambda: VisualAnalyzer(MockVisionProvider())
    try:
        with TestClient(app) as client:
            response = client.post("/api/phishing/visual-analysis", json={"url": "https://example.com"})
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json()["status"] == "unavailable"


def test_visual_api_uses_sandbox_screenshot() -> None:
    screenshot = ScreenshotArtifact.from_bytes("https://paypal-login-example.xyz", b"safe-mock-image")
    sandbox = BrowserSandboxAnalyzer(MockSandboxProvider(screenshots=[screenshot]))
    visual = VisualAnalyzer(MockVisionProvider({"detected_brand": "PayPal", "visual_similarity": 0.91, "logo_detected": True}))
    app.dependency_overrides[get_sandbox_analyzer] = lambda: sandbox
    app.dependency_overrides[get_visual_analyzer] = lambda: visual
    try:
        with TestClient(app) as client:
            response = client.post("/api/phishing/visual-analysis", json={"url": "https://paypal-login-example.xyz"})
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json()["detected_brand"] == "PayPal"
    assert response.json()["brand_impersonation"] is True
