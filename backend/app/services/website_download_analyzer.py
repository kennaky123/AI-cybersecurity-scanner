"""Static analysis and malware-scanner integration for sandbox downloads."""

from __future__ import annotations

import hashlib
import math
import re
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol

import pefile

from .browser_sandbox import SandboxAnalysis, SandboxDownload
from .malware_detector import MalwareDetector, MalwareModelUnavailableError

_STRINGS = re.compile(rb"[\x20-\x7f]{5,}")
_URLS = re.compile(rb"https?://[^\s\x00\"'<>]{4,}", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class MalwareScanResult:
    status: str
    prediction: str | None = None
    probability: float | None = None
    risk_score: int | None = None
    risk_level: str = "UNKNOWN"
    evidence: list[str] = field(default_factory=list)


class MalwareScanner(Protocol):
    def scan_file(self, download: SandboxDownload) -> MalwareScanResult:
        ...


class UnavailableMalwareScanner:
    def scan_file(self, download: SandboxDownload) -> MalwareScanResult:
        return MalwareScanResult("unavailable", evidence=["Malware scanner is not configured for sandbox artifacts."])


class ExistingMalwareScannerAdapter:
    """Adapter around the existing MalwareDetector; static-only and cleanup-safe."""

    def __init__(self, detector: MalwareDetector | None = None) -> None:
        self.detector = detector or MalwareDetector()

    def scan_file(self, download: SandboxDownload) -> MalwareScanResult:
        if not download.content_bytes:
            return MalwareScanResult("unavailable", evidence=["Sandbox did not expose file bytes to the static scanner."])
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(prefix="sandbox-static-", suffix=".bin", delete=False) as handle:
                handle.write(download.content_bytes)
                temporary_path = Path(handle.name)
            result = self.detector.analyze(temporary_path, download.filename or "download.bin", download.sha256 or hashlib.sha256(download.content_bytes).hexdigest())
            return MalwareScanResult("completed", result.prediction, result.probability, result.risk_score, result.risk_level, [f"Existing static malware detector returned {result.prediction}."])
        except MalwareModelUnavailableError as error:
            return MalwareScanResult("unavailable", evidence=[str(error)])
        except Exception:
            return MalwareScanResult("error", evidence=["Existing malware scanner failed; no execution was attempted."])
        finally:
            if temporary_path is not None:
                try:
                    temporary_path.unlink(missing_ok=True)
                except OSError:
                    pass


class MockMalwareScanner:
    def __init__(self, result: MalwareScanResult) -> None:
        self.result = result

    def scan_file(self, download: SandboxDownload) -> MalwareScanResult:
        return self.result


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    size = len(data)
    return -sum((count / size) * math.log2(count / size) for count in counts if count)


def _file_type(data: bytes, filename: str | None, mime: str | None) -> str:
    if data.startswith(b"MZ"):
        return "PE_EXECUTABLE"
    if data.startswith(b"%PDF"):
        return "PDF"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP_OR_ARCHIVE"
    if filename and "." in filename:
        return f"UNKNOWN_{filename.rsplit('.', 1)[-1].upper()}"
    return mime or "UNKNOWN"


def _signature_status(data: bytes) -> str:
    if not data.startswith(b"MZ"):
        return "NOT_APPLICABLE"
    try:
        pe = pefile.PE(data=data, fast_load=True)
        security_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        signed = int(pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_index].Size) > 0
        pe.close()
        return "PRESENT" if signed else "ABSENT"
    except Exception:
        return "UNKNOWN"


def static_file_metadata(download: SandboxDownload) -> dict[str, object]:
    data = download.content_bytes or b""
    digest = download.sha256 or (hashlib.sha256(data).hexdigest() if data else None)
    strings = [item.decode("ascii", errors="replace") for item in _STRINGS.findall(data)[:100]]
    urls = [item.decode("ascii", errors="replace") for item in _URLS.findall(data)[:50]]
    return {
        "filename": download.filename,
        "extension": Path(download.filename or "").suffix.lower() or None,
        "mime": download.mime,
        "size": download.size if download.size is not None else (len(data) if data else None),
        "sha256": digest,
        "file_type": _file_type(data, download.filename, download.mime),
        "digital_signature": _signature_status(data),
        "entropy": round(_entropy(data), 6) if data else None,
        "suspicious_strings": strings,
        "embedded_urls": urls,
        "bytes_available": bool(data),
        "execution_blocked": True,
    }


@dataclass(frozen=True, slots=True)
class DownloadAssessment:
    file: dict[str, object]
    malware_result: MalwareScanResult
    risk: str
    evidence: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class WebsiteDownloadReport:
    status: str
    website_risk: str
    downloads: list[DownloadAssessment] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    potential_impact: list[str] = field(default_factory=list)


class WebsiteDownloadAnalyzer:
    def __init__(self, malware_scanner: MalwareScanner | None = None) -> None:
        self.malware_scanner = malware_scanner or UnavailableMalwareScanner()

    def analyze(self, sandbox: SandboxAnalysis, *, website_risk: str = "UNKNOWN") -> WebsiteDownloadReport:
        if sandbox.status != "completed":
            return WebsiteDownloadReport(sandbox.status, website_risk, evidence=["No completed sandbox session was available; no download behavior was confirmed."])
        assessments: list[DownloadAssessment] = []
        evidence: list[str] = []
        impact: list[str] = []
        for download in sandbox.downloads:
            metadata = static_file_metadata(download)
            malware = self.malware_scanner.scan_file(download)
            risk = malware.risk_level if malware.status == "completed" else "UNKNOWN"
            item_evidence = ["Sandbox observed this download; the file was not executed.", *malware.evidence]
            if metadata["file_type"] == "PE_EXECUTABLE":
                item_evidence.append("Downloaded artifact is a PE executable and requires isolated review.")
                if risk in {"HIGH", "CRITICAL"} or malware.prediction == "MALWARE":
                    impact.append("Website delivered a suspicious executable.")
            evidence.extend(item_evidence)
            assessments.append(DownloadAssessment(metadata, malware, risk, item_evidence))
        if assessments:
            evidence.insert(0, f"Sandbox observed {len(assessments)} downloaded file(s).")
        return WebsiteDownloadReport("completed", website_risk, assessments, evidence, sorted(set(impact)))
