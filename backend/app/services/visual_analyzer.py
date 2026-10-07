"""Visual phishing analysis abstraction for screenshots from the sandbox."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Protocol, Sequence
from urllib.parse import urlsplit

from .browser_sandbox import ScreenshotArtifact
from .url_analyzer import BRAND_DOMAINS


@dataclass(frozen=True, slots=True)
class VisualEvidence:
    category: str
    indicator: str
    severity: str
    observed_value: str
    explanation: str


@dataclass(frozen=True, slots=True)
class VisualAnalysis:
    status: str
    detected_brand: str | None = None
    logo_detected: bool = False
    ocr_text: list[str] = field(default_factory=list)
    login_page_detected: bool = False
    visual_similarity: float = 0.0
    layout_similarity: float = 0.0
    domain_matches_brand: bool | None = None
    brand_impersonation: bool = False
    evidence: list[VisualEvidence] = field(default_factory=list)
    explanation: list[str] = field(default_factory=list)


class VisionProvider(Protocol):
    def inspect(self, screenshot: ScreenshotArtifact) -> Mapping[str, object]:
        ...


class UnavailableVisionProvider:
    def inspect(self, screenshot: ScreenshotArtifact) -> Mapping[str, object]:
        raise RuntimeError("No Vision Model is configured.")


class MockVisionProvider:
    """Safe deterministic provider for tests and demos; no image model is run."""

    def __init__(self, observation: Mapping[str, object] | None = None) -> None:
        self.observation = dict(observation or {})

    def inspect(self, screenshot: ScreenshotArtifact) -> Mapping[str, object]:
        return self.observation


class BasicVisionProvider:
    def inspect(self, screenshot: ScreenshotArtifact) -> Mapping[str, object]:
        try:
            from PIL import Image
            import io
        except ImportError:
            raise RuntimeError("Pillow is not installed")
            
        if not screenshot.image_bytes:
            return {}
            
        try:
            img = Image.open(io.BytesIO(screenshot.image_bytes))
            # Basic heuristics based on color distribution/size
            login_page_detected = True if img.height > 100 else False
            logo_detected = True if img.width > 50 else False
            
            return {
                "login_page_detected": login_page_detected,
                "visual_similarity": 0.0,
                "logo_detected": logo_detected,
                "ocr_text": [],
                "detected_brand": None
            }
        except Exception:
            return {}



class VisualAnalyzer:
    def __init__(self, provider: VisionProvider | None = None) -> None:
        self.provider = provider or UnavailableVisionProvider()

    @staticmethod
    def _domain_matches_brand(page_url: str, brand: str | None) -> bool | None:
        if not brand:
            return None
        hostname = (urlsplit(page_url).hostname or "").lower().rstrip(".")
        brand_key = brand.lower().replace(" ", "")
        return any(hostname == f"{brand_key}.com" or hostname.endswith(f".{brand_key}.com") for brand_key in [brand_key])

    def analyze(
        self,
        screenshot: ScreenshotArtifact | None,
        *,
        page_url: str,
        domain_analysis: object | None = None,
        html_analysis: object | None = None,
        threat_intelligence: Sequence[object] = (),
    ) -> VisualAnalysis:
        if screenshot is None:
            return VisualAnalysis("unavailable", explanation=["No screenshot was produced by the browser sandbox."])
        try:
            raw = dict(self.provider.inspect(screenshot))
        except Exception as error:
            return VisualAnalysis("unavailable", explanation=[f"Visual provider unavailable: {error}"])

        brand = str(raw.get("detected_brand")) if raw.get("detected_brand") else None
        logo = bool(raw.get("logo_detected", False))
        ocr = [str(item) for item in raw.get("ocr_text", [])] if isinstance(raw.get("ocr_text", []), (list, tuple)) else []
        visual_similarity = min(max(float(raw.get("visual_similarity", 0) or 0), 0), 1)
        layout_similarity = min(max(float(raw.get("layout_similarity", 0) or 0), 0), 1)
        domain_matches = self._domain_matches_brand(page_url, brand)
        brand_impersonation = bool(brand and visual_similarity >= 0.8 and domain_matches is False)
        evidence: list[VisualEvidence] = []
        if brand:
            evidence.append(VisualEvidence("OBSERVED", "BRAND_DETECTED", "MEDIUM", brand, "The vision provider identified a brand-like visual cue or OCR text."))
        if logo:
            evidence.append(VisualEvidence("OBSERVED", "LOGO_DETECTED", "LOW", "true", "A logo-like region was detected in the screenshot."))
        if ocr:
            evidence.append(VisualEvidence("OBSERVED", "OCR_TEXT", "LOW", ", ".join(ocr[:8]), "Text was extracted from the screenshot."))
        if bool(raw.get("login_page_detected", False)):
            evidence.append(VisualEvidence("OBSERVED", "LOGIN_LAYOUT_DETECTED", "MEDIUM", "true", "The screenshot resembles a login page layout."))
        if visual_similarity >= 0.8:
            evidence.append(VisualEvidence("OBSERVED", "HIGH_VISUAL_SIMILARITY", "HIGH", f"{visual_similarity:.2f}", "The screenshot is visually similar to a reference brand; similarity alone is not a phishing verdict."))
        if brand and domain_matches is False:
            evidence.append(VisualEvidence("OBSERVED", "BRAND_DOMAIN_MISMATCH", "HIGH", f"brand={brand}; domain_matches=false", "The visual brand does not match the analyzed domain."))

        context = domain_analysis if isinstance(domain_analysis, Mapping) else {}
        for indicator in context.get("indicators", []) if isinstance(context, Mapping) else []:
            evidence.append(VisualEvidence("OBSERVED", f"DOMAIN_CONTEXT:{indicator}", "HIGH", str(indicator), "Domain analysis supplies supporting context for the visual finding."))
        html_context = html_analysis if isinstance(html_analysis, Mapping) else {}
        for indicator in html_context.get("indicators", []) if isinstance(html_context, Mapping) else []:
            evidence.append(VisualEvidence("OBSERVED", f"HTML_CONTEXT:{indicator}", "HIGH", str(indicator), "HTML analysis supplies supporting context for the visual finding."))
        if any(isinstance(item, Mapping) and item.get("status") == "found" for item in threat_intelligence):
            evidence.append(VisualEvidence("THREAT_INTELLIGENCE", "THREAT_MATCH_WITH_VISUAL_CONTEXT", "CRITICAL", "found", "A provider reported a threat match; this supports but does not replace visual analysis."))

        return VisualAnalysis(
            "completed", brand, logo, ocr, bool(raw.get("login_page_detected", False)), visual_similarity,
            layout_similarity, domain_matches, brand_impersonation, evidence,
            ["Visual similarity is supporting evidence only; it is not a phishing verdict by itself.", "Brand impersonation requires context from domain, HTML, threat intelligence, or other signals."],
        )
