from __future__ import annotations

import json
import math
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Literal

DATABASE_PATH = Path(__file__).resolve().parents[2] / "scanner.db"
SCAN_TYPES = ("PHISHING", "MALWARE")
RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def _table_exists(connection: sqlite3.Connection, table: str) -> bool:
    return connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
    ).fetchone() is not None


def _migrate_legacy_history(connection: sqlite3.Connection) -> None:
    if not _table_exists(connection, "scan_history"):
        return
    if connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0] > 0:
        return

    legacy_columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(scan_history)").fetchall()
    }
    risk_score_select = "risk_score" if "risk_score" in legacy_columns else "NULL AS risk_score"
    risk_level_select = "risk_level" if "risk_level" in legacy_columns else "NULL AS risk_level"
    details_select = "details" if "details" in legacy_columns else "NULL AS details"
    rows = connection.execute(
        f"""
        SELECT id, scan_type, target, result, confidence, {risk_score_select},
               {risk_level_select}, {details_select}, created_at
        FROM scan_history ORDER BY id
        """
    ).fetchall()
    for row in rows:
        scan_type = str(row["scan_type"]).upper()
        if scan_type not in SCAN_TYPES or row["result"] is None or row["confidence"] is None:
            continue
        probability = min(max(float(row["confidence"]), 0.0), 1.0)
        risk_score = int(row["risk_score"]) if row["risk_score"] is not None else round(probability * 100)
        risk_level = row["risk_level"]
        if risk_level not in RISK_LEVELS:
            risk_level = (
                "LOW" if risk_score <= 29 else
                "MEDIUM" if risk_score <= 59 else
                "HIGH" if risk_score <= 79 else "CRITICAL"
            )
        target = str(row["target"])
        sha256 = None
        if scan_type == "MALWARE":
            sha256 = target
            try:
                details = json.loads(row["details"] or "{}")
                target = str(details.get("filename") or target)
            except (TypeError, json.JSONDecodeError):
                pass
        connection.execute(
            """
            INSERT INTO scans
                (id, scan_type, target, sha256, prediction, probability,
                 risk_score, risk_level, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row["id"], scan_type, target, sha256, row["result"], probability,
                risk_score, risk_level, row["created_at"],
            ),
        )


def initialize_database() -> None:
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL CHECK (scan_type IN ('PHISHING', 'MALWARE')),
                target TEXT NOT NULL,
                sha256 TEXT,
                prediction TEXT NOT NULL,
                probability REAL NOT NULL CHECK (probability >= 0 AND probability <= 1),
                risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
                risk_level TEXT NOT NULL CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_scans_type ON scans(scan_type)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_scans_risk ON scans(risk_level)")
        _migrate_legacy_history(connection)


def save_scan(
    *,
    scan_type: str,
    target: str,
    sha256: str | None,
    prediction: str,
    probability: float,
    risk_score: int,
    risk_level: str,
) -> int:
    normalized_type = scan_type.upper()
    normalized_risk = risk_level.upper()
    if normalized_type not in SCAN_TYPES:
        raise ValueError(f"Unsupported scan type: {scan_type}")
    if normalized_risk not in RISK_LEVELS:
        raise ValueError(f"Unsupported risk level: {risk_level}")
    if not 0 <= probability <= 1 or not 0 <= risk_score <= 100:
        raise ValueError("Probability or risk score is outside its valid range.")

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO scans
                (scan_type, target, sha256, prediction, probability, risk_score, risk_level)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (normalized_type, target, sha256, prediction.upper(), probability, risk_score, normalized_risk),
        )
        return int(cursor.lastrowid)


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def fetch_scan_history(
    *,
    page: int = 1,
    page_size: int = 20,
    scan_type: str | None = None,
    risk_level: str | None = None,
    search: str | None = None,
    sort_order: Literal["asc", "desc"] = "desc",
) -> dict[str, object]:
    clauses: list[str] = []
    parameters: list[object] = []
    if scan_type:
        clauses.append("scan_type = ?")
        parameters.append(scan_type.upper())
    if risk_level:
        clauses.append("risk_level = ?")
        parameters.append(risk_level.upper())
    if search and search.strip():
        pattern = f"%{_escape_like(search.strip())}%"
        clauses.append(
            "(target LIKE ? ESCAPE '\\' OR COALESCE(sha256, '') LIKE ? ESCAPE '\\' "
            "OR prediction LIKE ? ESCAPE '\\')"
        )
        parameters.extend((pattern, pattern, pattern))

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    direction = "ASC" if sort_order == "asc" else "DESC"
    offset = (page - 1) * page_size
    with get_connection() as connection:
        total = int(connection.execute(f"SELECT COUNT(*) FROM scans {where}", parameters).fetchone()[0])
        rows = connection.execute(
            f"""
            SELECT id, scan_type, target, sha256, prediction, probability,
                   risk_score, risk_level, created_at
            FROM scans {where}
            ORDER BY created_at {direction}, id {direction}
            LIMIT ? OFFSET ?
            """,
            [*parameters, page_size, offset],
        ).fetchall()
    return {
        "items": [dict(row) for row in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": math.ceil(total / page_size) if total else 0,
    }


def fetch_dashboard_data(recent_limit: int = 8) -> dict[str, object]:
    with get_connection() as connection:
        summary_row = connection.execute(
            """
            SELECT
                COUNT(*) AS total_scans,
                SUM(CASE WHEN scan_type = 'PHISHING' THEN 1 ELSE 0 END) AS url_scans,
                SUM(CASE WHEN scan_type = 'MALWARE' THEN 1 ELSE 0 END) AS file_scans,
                SUM(CASE WHEN prediction IN ('LEGITIMATE', 'BENIGN') THEN 1 ELSE 0 END) AS safe_results,
                SUM(CASE WHEN risk_level = 'HIGH' THEN 1 ELSE 0 END) AS high_risk_results,
                SUM(CASE WHEN risk_level = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_results
            FROM scans
            """
        ).fetchone()
        recent = connection.execute(
            """
            SELECT id, scan_type, target, sha256, prediction, probability,
                   risk_score, risk_level, created_at
            FROM scans ORDER BY created_at DESC, id DESC LIMIT ?
            """,
            (recent_limit,),
        ).fetchall()
        timeline = connection.execute(
            """
            SELECT substr(created_at, 1, 10) AS date,
                   COUNT(*) AS total,
                   SUM(CASE WHEN scan_type = 'PHISHING' THEN 1 ELSE 0 END) AS phishing,
                   SUM(CASE WHEN scan_type = 'MALWARE' THEN 1 ELSE 0 END) AS malware
            FROM scans GROUP BY substr(created_at, 1, 10) ORDER BY date ASC
            """
        ).fetchall()
        risk_rows = connection.execute(
            "SELECT risk_level AS name, COUNT(*) AS value FROM scans GROUP BY risk_level"
        ).fetchall()
        type_rows = connection.execute(
            "SELECT scan_type AS name, COUNT(*) AS value FROM scans GROUP BY scan_type"
        ).fetchall()
        prediction_rows = connection.execute(
            "SELECT prediction AS name, COUNT(*) AS value FROM scans GROUP BY prediction ORDER BY value DESC"
        ).fetchall()

    summary = {key: int(summary_row[key] or 0) for key in summary_row.keys()}
    risk_counts = {row["name"]: int(row["value"]) for row in risk_rows}
    type_counts = {row["name"]: int(row["value"]) for row in type_rows}
    return {
        "summary": summary,
        "recent_scans": [dict(row) for row in recent],
        "scan_count_over_time": [dict(row) for row in timeline],
        "risk_distribution": [{"name": name, "value": risk_counts.get(name, 0)} for name in RISK_LEVELS],
        "scan_type_distribution": [{"name": name, "value": type_counts.get(name, 0)} for name in SCAN_TYPES],
        "prediction_distribution": [dict(row) for row in prediction_rows],
    }
