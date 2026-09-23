from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from backend.app.api.malware import _validate_filename, get_malware_detector
from backend.app.api.phishing import get_phishing_detector
from backend.app.database import database
from backend.app.main import app
from backend.app.services.malware_detector import MalwareDetector


class ExplodingDetector:
    def analyze(self, *args, **kwargs):
        raise RuntimeError("secret internal path C:\\sensitive\\model.joblib")


def test_invalid_url_is_rejected_without_calling_model() -> None:
    app.dependency_overrides[get_phishing_detector] = lambda: ExplodingDetector()
    try:
        with TestClient(app) as client:
            response = client.post("/api/phishing/analyze", json={"url": "not-a-url"})
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 422
    assert "sensitive" not in response.text
    assert "traceback" not in response.text.lower()


@pytest.mark.parametrize(
    "filename",
    [
        "../evil.exe",
        "..\\evil.exe",
        "bad\x00.exe",
        "bad\nname.exe",
        "invoice\u202etxt.exe",
        "a" * 256 + ".exe",
    ],
)
def test_unsafe_filename_is_rejected(filename: str) -> None:
    with pytest.raises(HTTPException) as error:
        _validate_filename(filename)
    assert error.value.status_code == 400


def test_fake_exe_with_mz_but_invalid_pe_is_rejected_before_missing_model(tmp_path: Path) -> None:
    detector = MalwareDetector(
        tmp_path / "missing-model.joblib",
        tmp_path / "missing-preprocessor.joblib",
        tmp_path / "missing-metadata.json",
    )
    app.dependency_overrides[get_malware_detector] = lambda: detector
    try:
        with TestClient(app) as client:
            response = client.post(
                "/api/malware/analyze",
                files={"file": ("fake.exe", b"MZ-not-a-real-portable-executable", "application/octet-stream")},
            )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 422
    assert "Invalid PE structure" in response.json()["detail"]
    assert "traceback" not in response.text.lower()


def test_cors_allows_only_configured_frontend_origins() -> None:
    preflight_headers = {
        "Origin": "http://localhost:5173",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type",
    }
    with TestClient(app) as client:
        allowed = client.options("/api/phishing/analyze", headers=preflight_headers)
        blocked = client.options(
            "/api/phishing/analyze",
            headers={**preflight_headers, "Origin": "https://attacker.example"},
        )

    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert blocked.status_code == 400
    assert "access-control-allow-origin" not in blocked.headers


def test_unhandled_exception_returns_generic_json_without_stack_trace() -> None:
    app.dependency_overrides[get_phishing_detector] = lambda: ExplodingDetector()
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            response = client.post("/api/phishing/analyze", json={"url": "https://example.com"})
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error."}
    assert "sensitive" not in response.text
    assert "traceback" not in response.text.lower()


def test_database_constraints_reject_invalid_security_values(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "scanner.db")
    database.initialize_database()

    with pytest.raises(ValueError, match="Unsupported scan type"):
        database.save_scan(
            scan_type="UNKNOWN",
            target="target",
            sha256=None,
            prediction="BENIGN",
            probability=0.1,
            risk_score=10,
            risk_level="LOW",
        )
    with pytest.raises(ValueError, match="outside"):
        database.save_scan(
            scan_type="MALWARE",
            target="sample.exe",
            sha256="a" * 64,
            prediction="MALWARE",
            probability=1.5,
            risk_score=150,
            risk_level="CRITICAL",
        )
