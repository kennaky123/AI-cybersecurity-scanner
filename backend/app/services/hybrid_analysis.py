"""Hybrid Analysis / CrowdStrike Falcon Sandbox API v2 Integration.

Features:
- Hash-first strategy: Searches existing detonation reports by SHA256 first.
- Optional file submission: Only submits sample if HYBRID_ANALYSIS_SUBMIT_FILES=true.
- Polling mechanism: Polls /report/{id}/state with timeout, intervals, and exponential backoff.
- Pure evidence telemetry parsing: Extracts REAL processes, registry accesses,
  network connections, DNS queries, created/dropped files, and MITRE ATT&CK techniques.
- Never logs, exposes, or hallucinates API keys or fake behavior.
- Non-disruptive error handling: Gracefully returns structured FAILED / NOT_PERFORMED results.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class HybridAnalysisConfig:
    """Configuration settings for Hybrid Analysis sandbox integration."""

    api_key: str = ""
    enabled: bool = True
    base_url: str = "https://www.hybrid-analysis.com/api/v2"
    timeout: int = 30
    poll_interval: float = 5.0
    max_wait: int = 60
    submit_files: bool = False
    environment_id: str = "160"  # Windows 10 64-bit default

    @classmethod
    def from_env(cls) -> HybridAnalysisConfig:
        key = (
            os.getenv("HYBRID_ANALYSIS_API_KEY")
            or os.getenv("FALCON_SANDBOX_API_KEY")
            or ""
        ).strip()
        enabled_val = os.getenv("HYBRID_ANALYSIS_ENABLED", "true").strip().lower()
        enabled = enabled_val in {"true", "1", "yes", "on"}

        base_url = os.getenv(
            "HYBRID_ANALYSIS_BASE_URL", "https://www.hybrid-analysis.com/api/v2"
        ).rstrip("/")
        timeout = int(os.getenv("HYBRID_ANALYSIS_TIMEOUT", "30"))
        poll_interval = float(os.getenv("HYBRID_ANALYSIS_POLL_INTERVAL", "5.0"))
        max_wait = int(os.getenv("HYBRID_ANALYSIS_MAX_WAIT", "60"))
        submit_files = (
            os.getenv("HYBRID_ANALYSIS_SUBMIT_FILES", "false").strip().lower()
            in {"true", "1", "yes", "on"}
        )
        env_id = os.getenv("HYBRID_ANALYSIS_ENV_ID", "160")

        return cls(
            api_key=key,
            enabled=enabled,
            base_url=base_url,
            timeout=timeout,
            poll_interval=poll_interval,
            max_wait=max_wait,
            submit_files=submit_files,
            environment_id=env_id,
        )


@dataclass(frozen=True, slots=True)
class HybridAnalysisDetonation:
    """Normalized output from Hybrid Analysis Falcon Sandbox execution."""

    execution_status: str  # "COMPLETED", "FAILED", "NOT_PERFORMED", "TIMEOUT"
    dynamic_analysis_status: str  # "COMPLETED", "FAILED", "NOT_PERFORMED", "TIMEOUT"
    backend_type: str = "HYBRID_ANALYSIS"
    analysis_id: str | None = None
    report_url: str | None = None
    sample_sha256: str = ""
    verdict: str | None = None
    threat_score: int | None = None
    malware_family: str | None = None
    environment_description: str = "Falcon Sandbox Windows VM"
    process_events: list[dict[str, Any]] = field(default_factory=list)
    file_events: list[dict[str, Any]] = field(default_factory=list)
    registry_events: list[dict[str, Any]] = field(default_factory=list)
    network_events: list[dict[str, Any]] = field(default_factory=list)
    dns_events: list[dict[str, Any]] = field(default_factory=list)
    command_events: list[dict[str, Any]] = field(default_factory=list)
    persistence_events: list[dict[str, Any]] = field(default_factory=list)
    mitre_attcks: list[dict[str, Any]] = field(default_factory=list)
    signatures: list[dict[str, Any]] = field(default_factory=list)
    av_detect: int | None = None
    scanners: list[dict[str, Any]] = field(default_factory=list)
    classification_tags: list[str] = field(default_factory=list)
    error_code: str | None = None
    error_message: str | None = None


class HybridAnalysisClient:
    """Robust client interacting with the Hybrid Analysis API v2."""

    def __init__(self, config: HybridAnalysisConfig | None = None) -> None:
        self.config = config or HybridAnalysisConfig.from_env()

    def _get_headers(self) -> dict[str, str]:
        return {
            "api-key": self.config.api_key,
            "User-Agent": "Falcon Sandbox",
            "accept": "application/json",
        }

    def execute(
        self,
        sha256: str,
        sample_path: str | Path | None = None,
        timeout: int | None = None,
    ) -> HybridAnalysisDetonation:
        effective_timeout = timeout or self.config.timeout
        clean_hash = sha256.strip().lower()

        if not self.config.enabled:
            return HybridAnalysisDetonation(
                execution_status="NOT_PERFORMED",
                dynamic_analysis_status="NOT_PERFORMED",
                sample_sha256=clean_hash,
                error_code="DISABLED",
                error_message="Hybrid Analysis integration is disabled via HYBRID_ANALYSIS_ENABLED.",
            )

        if not self.config.api_key:
            return HybridAnalysisDetonation(
                execution_status="NOT_PERFORMED",
                dynamic_analysis_status="NOT_PERFORMED",
                sample_sha256=clean_hash,
                error_code="API_KEY_MISSING",
                error_message="HYBRID_ANALYSIS_API_KEY is not configured.",
            )

        if not clean_hash and sample_path and Path(sample_path).is_file():
            import hashlib
            try:
                clean_hash = hashlib.sha256(Path(sample_path).read_bytes()).hexdigest()
            except Exception as err:
                logger.error("Failed to compute hash from sample: %s", err)

        if not clean_hash:
            return HybridAnalysisDetonation(
                execution_status="NOT_PERFORMED",
                dynamic_analysis_status="NOT_PERFORMED",
                error_code="NO_TARGET",
                error_message="No SHA256 or valid sample file provided for detonation.",
            )

        # ----------------------------------------------------------------------
        # Step 1: Hash-First Strategy (Query Existing Detonation Reports)
        # ----------------------------------------------------------------------
        logger.info("Hybrid Analysis: querying existing report for hash %s", clean_hash[:16])
        report_job_id, overview_meta = self._lookup_existing_report(clean_hash, effective_timeout)

        if report_job_id:
            logger.info("Hybrid Analysis: existing report found (job_id: %s)", report_job_id)
            return self._fetch_and_parse_report(report_job_id, clean_hash, overview_meta, effective_timeout)

        # ----------------------------------------------------------------------
        # Step 2: Handle No Existing Report
        # ----------------------------------------------------------------------
        if not self.config.submit_files:
            logger.info(
                "Hybrid Analysis: sample %s has no existing report and HYBRID_ANALYSIS_SUBMIT_FILES is False",
                clean_hash[:16],
            )
            return HybridAnalysisDetonation(
                execution_status="NOT_PERFORMED",
                dynamic_analysis_status="NOT_PERFORMED",
                sample_sha256=clean_hash,
                error_code="NO_EXISTING_REPORT",
                error_message="No existing sandbox report found for this hash. Live file submission is disabled (HYBRID_ANALYSIS_SUBMIT_FILES=false).",
            )

        # ----------------------------------------------------------------------
        # Step 3: Optional File Submission & Polling
        # ----------------------------------------------------------------------
        if not sample_path or not Path(sample_path).is_file():
            return HybridAnalysisDetonation(
                execution_status="NOT_PERFORMED",
                dynamic_analysis_status="NOT_PERFORMED",
                sample_sha256=clean_hash,
                error_code="FILE_NOT_FOUND",
                error_message="Sample file not found on server for submission.",
            )

        return self._submit_file_and_poll(Path(sample_path), clean_hash, effective_timeout)

    def _lookup_existing_report(
        self, sha256: str, timeout: int
    ) -> tuple[str | None, dict[str, Any] | None]:
        """Queries /search/hash?hash= and /overview/{sha256}."""
        # Method A: search/hash?hash=
        try:
            url = f"{self.config.base_url}/search/hash"
            resp = requests.get(
                url,
                params={"hash": sha256},
                headers=self._get_headers(),
                timeout=timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                reports = (
                    data.get("reports", [])
                    if isinstance(data, dict)
                    else (data if isinstance(data, list) else [])
                )
                if reports and isinstance(reports[0], dict):
                    jid = reports[0].get("id") or reports[0].get("job_id")
                    if jid:
                        return str(jid), reports[0]
            elif resp.status_code == 401:
                logger.error("Hybrid Analysis authentication failed: HTTP 401 Unauthorized")
                return None, {"error_code": "UNAUTHORIZED"}
            elif resp.status_code == 429:
                logger.warning("Hybrid Analysis rate limit reached: HTTP 429")
                return None, {"error_code": "RATE_LIMIT"}
        except requests.exceptions.Timeout:
            logger.warning("Hybrid Analysis search request timed out")
        except Exception as err:
            logger.warning("Hybrid Analysis search hash request failed: %s", err)

        # Method B: overview/{sha256} fallback
        try:
            ov_url = f"{self.config.base_url}/overview/{sha256}"
            ov_resp = requests.get(
                ov_url,
                headers=self._get_headers(),
                timeout=timeout,
            )
            if ov_resp.status_code == 200:
                ov_data = ov_resp.json()
                rep_ids = ov_data.get("reports", [])
                if rep_ids and isinstance(rep_ids[0], str):
                    return rep_ids[0], ov_data
        except Exception as err:
            logger.warning("Hybrid Analysis overview request failed: %s", err)

        return None, None

    def _submit_file_and_poll(
        self, file_path: Path, sha256: str, timeout: int
    ) -> HybridAnalysisDetonation:
        """Uploads file to /submit/file and polls for status completion."""
        if file_path.stat().st_size > 100 * 1024 * 1024:
            return HybridAnalysisDetonation(
                execution_status="FAILED",
                dynamic_analysis_status="FAILED",
                sample_sha256=sha256,
                error_code="FILE_TOO_LARGE",
                error_message="File exceeds the maximum allowable upload size (100 MB).",
            )

        submit_url = f"{self.config.base_url}/submit/file"
        logger.info("Submitting file %s to Hybrid Analysis...", file_path.name)

        try:
            with open(file_path, "rb") as f:
                files = {"file": (file_path.name, f, "application/octet-stream")}
                data = {"environment_id": self.config.environment_id}
                resp = requests.post(
                    submit_url,
                    headers={"api-key": self.config.api_key, "User-Agent": "Falcon Sandbox"},
                    files=files,
                    data=data,
                    timeout=timeout,
                )
        except Exception as err:
            logger.error("Submission request failed: %s", err)
            return HybridAnalysisDetonation(
                execution_status="FAILED",
                dynamic_analysis_status="FAILED",
                sample_sha256=sha256,
                error_code="SUBMIT_ERROR",
                error_message=f"Submission request error: {err}",
            )

        if resp.status_code not in (200, 201):
            logger.warning("Submission failed with status %d: %s", resp.status_code, resp.text[:200])
            return HybridAnalysisDetonation(
                execution_status="FAILED",
                dynamic_analysis_status="FAILED",
                sample_sha256=sha256,
                error_code=f"HTTP_{resp.status_code}",
                error_message=f"Hybrid Analysis submission rejected with status {resp.status_code}",
            )

        try:
            submit_data = resp.json()
            job_id = (
                submit_data.get("job_id")
                or submit_data.get("id")
                or (submit_data.get("data", {}).get("job_id") if isinstance(submit_data.get("data"), dict) else None)
            )
        except Exception:
            job_id = None

        if not job_id:
            return HybridAnalysisDetonation(
                execution_status="FAILED",
                dynamic_analysis_status="FAILED",
                sample_sha256=sha256,
                error_code="MALFORMED_SUBMISSION_RESPONSE",
                error_message="Hybrid Analysis submission response did not contain a valid job ID.",
            )

        logger.info("Submission successful! Assigned job_id: %s. Initiating polling...", job_id)
        return self._poll_job(str(job_id), sha256, timeout)

    def _poll_job(self, job_id: str, sha256: str, timeout: int) -> HybridAnalysisDetonation:
        """Polls /report/{id}/state until finished or max_wait expired."""
        start_time = time.time()
        poll_interval = self.config.poll_interval
        attempts = 0

        while (time.time() - start_time) < self.config.max_wait:
            attempts += 1
            state_url = f"{self.config.base_url}/report/{job_id}/state"
            try:
                resp = requests.get(state_url, headers=self._get_headers(), timeout=timeout)
                if resp.status_code == 200:
                    state_info = resp.json()
                    current_state = str(state_info.get("state", "")).upper()
                    logger.debug("Poll #%d for job %s: state=%s", attempts, job_id, current_state)
                    if current_state in {"SUCCESS", "COMPLETED"}:
                        return self._fetch_and_parse_report(job_id, sha256, None, timeout)
                    if current_state in {"ERROR", "FAILED"}:
                        err_detail = state_info.get("error") or "Falcon Sandbox VM failed execution"
                        return HybridAnalysisDetonation(
                            execution_status="FAILED",
                            dynamic_analysis_status="FAILED",
                            analysis_id=job_id,
                            sample_sha256=sha256,
                            error_code="EXECUTION_FAILED",
                            error_message=f"Sandbox execution error: {err_detail}",
                        )
                elif resp.status_code == 429:
                    logger.warning("Rate limit hit during polling; backing off")
                    poll_interval = min(poll_interval * 1.5, 20.0)
            except Exception as err:
                logger.warning("Polling error on attempt #%d: %s", attempts, err)

            time.sleep(poll_interval)

        logger.warning("Polling timed out for job %s after %d seconds", job_id, self.config.max_wait)
        return HybridAnalysisDetonation(
            execution_status="TIMEOUT",
            dynamic_analysis_status="TIMEOUT",
            analysis_id=job_id,
            sample_sha256=sha256,
            error_code="ANALYSIS_TIMEOUT",
            error_message=f"Analysis timed out after waiting {self.config.max_wait}s for Falcon Sandbox completion.",
        )

    def _fetch_and_parse_report(
        self,
        job_id: str,
        sha256: str,
        overview_meta: dict[str, Any] | None,
        timeout: int,
    ) -> HybridAnalysisDetonation:
        """Fetches /report/{id}/summary and normalizes real telemetry events."""
        rep_url = f"{self.config.base_url}/report/{job_id}/summary"
        try:
            resp = requests.get(rep_url, headers=self._get_headers(), timeout=timeout)
            if resp.status_code != 200:
                logger.warning("Failed to fetch report summary for job %s: status %d", job_id, resp.status_code)
                return HybridAnalysisDetonation(
                    execution_status="FAILED",
                    dynamic_analysis_status="FAILED",
                    analysis_id=job_id,
                    sample_sha256=sha256,
                    error_code=f"HTTP_{resp.status_code}",
                    error_message=f"Failed to retrieve report summary: status {resp.status_code}",
                )
            summary = resp.json()
        except Exception as err:
            logger.error("Exception fetching report summary: %s", err)
            return HybridAnalysisDetonation(
                execution_status="FAILED",
                dynamic_analysis_status="FAILED",
                analysis_id=job_id,
                sample_sha256=sha256,
                error_code="REPORT_FETCH_ERROR",
                error_message=f"Network error reading report: {err}",
            )

        return self._normalize_summary_data(job_id, sha256, summary, overview_meta)

    def _normalize_summary_data(
        self,
        job_id: str,
        sha256: str,
        summary: dict[str, Any],
        overview_meta: dict[str, Any] | None,
    ) -> HybridAnalysisDetonation:
        """Transforms raw Falcon Sandbox JSON into clean, un-faked telemetry."""
        process_events: list[dict[str, Any]] = []
        file_events: list[dict[str, Any]] = []
        registry_events: list[dict[str, Any]] = []
        network_events: list[dict[str, Any]] = []
        dns_events: list[dict[str, Any]] = []
        command_events: list[dict[str, Any]] = []
        persistence_events: list[dict[str, Any]] = []
        mitre_attcks: list[dict[str, Any]] = []
        signatures: list[dict[str, Any]] = []

        # 1. Process tree & Command lines & Child registry/files
        raw_procs = summary.get("processes", []) or []
        for p in raw_procs:
            if isinstance(p, dict):
                p_name = p.get("name") or p.get("normalized_path") or "unnamed.exe"
                p_pid = p.get("pid")
                p_cmd = p.get("command_line") or ""
                p_entry = {
                    "image": p_name,
                    "pid": p_pid,
                    "command_line": p_cmd,
                    "sha256": p.get("sha256"),
                }
                process_events.append(p_entry)
                if p_cmd:
                    command_events.append({"command": p_cmd, "pid": p_pid})

                # Process-level registry accesses
                for r in p.get("registry", []) or []:
                    if isinstance(r, dict) and r.get("path"):
                        registry_events.append({
                            "key": r.get("path"),
                            "operation": r.get("status") or "access",
                        })

                # Process-level created files
                for cf in p.get("created_files", []) or []:
                    if isinstance(cf, dict) and cf.get("file"):
                        file_events.append({
                            "path": cf.get("file"),
                            "operation": "create",
                        })

        # 2. Extracted / Dropped files
        for ef in summary.get("extracted_files", []) or []:
            if isinstance(ef, dict):
                f_name = ef.get("name") or ef.get("file_path") or "unknown"
                file_events.append({
                    "path": f_name,
                    "size": ef.get("file_size"),
                    "sha256": ef.get("sha256"),
                    "operation": "dropped",
                })

        # 3. Network connections
        for h in summary.get("hosts", []) or []:
            if isinstance(h, dict):
                network_events.append({
                    "destination": h.get("ip") or h.get("host"),
                    "port": h.get("port", 80),
                    "protocol": h.get("protocol", "TCP"),
                })
        for ch in summary.get("compromised_hosts", []) or []:
            if isinstance(ch, dict):
                network_events.append({
                    "destination": ch.get("ip"),
                    "port": ch.get("port", 443),
                    "protocol": "TCP",
                })

        # 4. DNS queries
        for d in summary.get("dns_requests", []) or []:
            if isinstance(d, dict) and d.get("request"):
                dns_events.append({
                    "domain": d.get("request"),
                    "response": d.get("response"),
                })
        for dom in summary.get("domains", []) or []:
            if isinstance(dom, str):
                dns_events.append({"domain": dom})

        # 5. MITRE ATT&CK Matrix
        for m in summary.get("mitre_attcks", []) or []:
            if isinstance(m, dict):
                t_id = m.get("attck_id") or m.get("technique_id") or ""
                t_name = m.get("technique") or ""
                tactic = m.get("tactic") or ""
                mitre_attcks.append({
                    "technique_id": t_id,
                    "technique_name": t_name,
                    "tactic": tactic,
                    "wiki_url": m.get("attck_id_wiki"),
                    "source": "hybrid_analysis",
                })
                if "persistence" in tactic.lower() or "persistence" in t_name.lower() or "run" in t_name.lower():
                    persistence_events.append({
                        "technique": t_id,
                        "description": t_name,
                    })

        # 6. Signatures
        for s in summary.get("signatures", []) or []:
            if isinstance(s, dict):
                signatures.append({
                    "identifier": s.get("identifier"),
                    "threat_level": s.get("threat_level"),
                    "threat_level_readable": s.get("threat_level_readable"),
                    "category": s.get("category"),
                    "description": s.get("description"),
                })

        verdict = summary.get("verdict") or (overview_meta.get("verdict") if overview_meta else None)
        threat_score = summary.get("threat_score")
        if threat_score is None and overview_meta:
            threat_score = overview_meta.get("threat_score")
        vx_family = summary.get("vx_family") or (overview_meta.get("vx_family") if overview_meta else None)

        av_detect = summary.get("av_detect")
        if av_detect is None and overview_meta:
            av_detect = overview_meta.get("av_detect")

        raw_scanners = summary.get("scanners") or (overview_meta.get("scanners") if overview_meta else None) or []
        scanners_list: list[dict[str, Any]] = []
        if isinstance(raw_scanners, list):
            for sc in raw_scanners:
                if isinstance(sc, dict):
                    scanners_list.append({
                        "name": sc.get("name") or "Scanner",
                        "status": sc.get("status") or "unknown",
                        "positives": sc.get("positives"),
                        "total": sc.get("total"),
                        "percent": sc.get("percent"),
                    })

        tags_set: list[str] = []
        for t_src in [summary.get("classification_tags"), summary.get("tags"), (overview_meta.get("tags") if overview_meta else None)]:
            if isinstance(t_src, list):
                for t in t_src:
                    if isinstance(t, str) and t not in tags_set:
                        tags_set.append(t)

        env_desc = summary.get("environment_description") or "Falcon Sandbox Windows VM"
        report_url = f"https://www.hybrid-analysis.com/sample/{sha256}/{job_id}"

        return HybridAnalysisDetonation(
            execution_status="COMPLETED",
            dynamic_analysis_status="COMPLETED",
            backend_type=f"HYBRID_ANALYSIS ({env_desc})",
            analysis_id=job_id,
            report_url=report_url,
            sample_sha256=sha256,
            verdict=verdict,
            threat_score=threat_score,
            malware_family=vx_family,
            environment_description=env_desc,
            process_events=process_events,
            file_events=file_events,
            registry_events=registry_events,
            network_events=network_events,
            dns_events=dns_events,
            command_events=command_events,
            persistence_events=persistence_events,
            mitre_attcks=mitre_attcks,
            signatures=signatures,
            av_detect=av_detect,
            scanners=scanners_list,
            classification_tags=tags_set,
        )

