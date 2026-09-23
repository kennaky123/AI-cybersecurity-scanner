from pathlib import Path

from fastapi.testclient import TestClient

from backend.app.database import database
from backend.app.main import app


def _seed_scans() -> None:
    scans = [
        ("PHISHING", "https://safe.example", None, "LEGITIMATE", 0.10, 10, "LOW"),
        ("PHISHING", "https://login.example", None, "PHISHING", 0.70, 70, "HIGH"),
        ("MALWARE", "safe.exe", "a" * 64, "BENIGN", 0.20, 20, "LOW"),
        ("MALWARE", "danger.exe", "b" * 64, "MALWARE", 0.95, 95, "CRITICAL"),
        ("MALWARE", "review.exe", "c" * 64, "MALWARE", 0.50, 50, "MEDIUM"),
    ]
    for scan_type, target, sha256, prediction, probability, score, level in scans:
        database.save_scan(
            scan_type=scan_type,
            target=target,
            sha256=sha256,
            prediction=prediction,
            probability=probability,
            risk_score=score,
            risk_level=level,
        )


def test_dashboard_aggregates_and_chart_data(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "scanner.db")
    with TestClient(app) as client:
        _seed_scans()
        response = client.get("/api/dashboard")

    assert response.status_code == 200
    data = response.json()
    assert data["summary"] == {
        "total_scans": 5,
        "url_scans": 2,
        "file_scans": 3,
        "safe_results": 2,
        "high_risk_results": 1,
        "critical_results": 1,
    }
    assert len(data["recent_scans"]) == 5
    assert sum(item["value"] for item in data["risk_distribution"]) == 5
    assert {item["name"]: item["value"] for item in data["scan_type_distribution"]} == {
        "PHISHING": 2,
        "MALWARE": 3,
    }
    assert sum(item["total"] for item in data["scan_count_over_time"]) == 5
    assert sum(item["value"] for item in data["prediction_distribution"]) == 5


def test_history_pagination_filters_search_and_sort(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "scanner.db")
    with TestClient(app) as client:
        _seed_scans()
        page = client.get("/api/history?page=1&page_size=2")
        malware = client.get("/api/history?scan_type=MALWARE&page_size=10")
        critical = client.get("/api/history?risk_level=CRITICAL")
        search = client.get("/api/history?search=danger.exe")
        oldest = client.get("/api/history?sort_order=asc&page_size=10")

    assert page.status_code == 200
    assert page.json()["total"] == 5
    assert page.json()["total_pages"] == 3
    assert len(page.json()["items"]) == 2
    assert malware.json()["total"] == 3
    assert all(item["scan_type"] == "MALWARE" for item in malware.json()["items"])
    assert critical.json()["items"][0]["target"] == "danger.exe"
    assert search.json()["total"] == 1
    assert search.json()["items"][0]["sha256"] == "b" * 64
    assert oldest.json()["items"][0]["target"] == "https://safe.example"


def test_legacy_scan_history_is_migrated_once(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "scanner.db")
    with database.get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE scan_history (
                id INTEGER PRIMARY KEY, scan_type TEXT, target TEXT, result TEXT,
                confidence REAL, created_at TEXT
            )
            """
        )
        connection.execute(
            """
            INSERT INTO scan_history VALUES
                (1, 'malware', ?, 'MALWARE', 0.9, '2026-01-01 00:00:00')
            """,
            ("d" * 64,),
        )

    database.initialize_database()
    database.initialize_database()
    migrated = database.fetch_scan_history(page_size=10)

    assert migrated["total"] == 1
    assert migrated["items"][0]["target"] == "d" * 64
    assert migrated["items"][0]["sha256"] == "d" * 64
    assert migrated["items"][0]["risk_score"] == 90
    assert migrated["items"][0]["risk_level"] == "CRITICAL"
