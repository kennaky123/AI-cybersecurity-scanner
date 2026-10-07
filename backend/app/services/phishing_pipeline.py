"""Phase 5 orchestration for a complete phishing assessment."""

from __future__ import annotations

from dataclasses import dataclass

from .html_analyzer import HTMLAnalysis, HTMLAnalyzer, HTMLFetchError
from .javascript_analyzer import JavaScriptAnalysis, JavaScriptAnalyzer
from .risk_engine import RiskEngine, RiskReport
from .threat_intelligence import ThreatIntelManager, ThreatIntelResult


@dataclass(frozen=True, slots=True)
class PhishingPipelineResult:
    html_analysis: HTMLAnalysis
    javascript_analysis: JavaScriptAnalysis
    threat_intelligence: list[ThreatIntelResult]
    risk_report: RiskReport


class PhishingPipeline:
    def __init__(
        self,
        html_analyzer: HTMLAnalyzer | None = None,
        javascript_analyzer: JavaScriptAnalyzer | None = None,
        threat_intel: ThreatIntelManager | None = None,
        risk_engine: RiskEngine | None = None,
    ) -> None:
        self.html_analyzer = html_analyzer or HTMLAnalyzer()
        self.javascript_analyzer = javascript_analyzer or JavaScriptAnalyzer()
        self.threat_intel = threat_intel or ThreatIntelManager()
        self.risk_engine = risk_engine or RiskEngine()

    @staticmethod
    def _unavailable_html(url: str, message: str) -> HTMLAnalysis:
        return HTMLAnalysis(0, url, status="UNAVAILABLE", explanation=[message])

    @staticmethod
    def _unavailable_javascript(message: str) -> JavaScriptAnalysis:
        return JavaScriptAnalysis(0, explanation=[message])

    def analyze(self, url: str, *, url_analysis: object, domain_analysis: object, model_probability: float | None) -> PhishingPipelineResult:
        try:
            html = self.html_analyzer.analyze_url(url)
            javascript = self.javascript_analyzer.analyze(html.inline_scripts, html.external_scripts, html.final_url)
        except HTMLFetchError as error:
            html = self._unavailable_html(url, str(error))
            javascript = self._unavailable_javascript("JavaScript analysis unavailable because HTML could not be fetched.")
        except Exception:
            html = self._unavailable_html(url, "HTML analysis failed; no safety conclusion is drawn from the failure.")
            javascript = self._unavailable_javascript("JavaScript analysis failed; no safety conclusion is drawn from the failure.")
        try:
            intelligence = self.threat_intel.lookup("URL", url)
        except Exception:
            intelligence = []
        report = self.risk_engine.assess(
            url_analysis=url_analysis,
            domain_analysis=domain_analysis,
            html_analysis=html,
            javascript_analysis=javascript,
            threat_intelligence=intelligence,
            model_probability=model_probability,
        )
        return PhishingPipelineResult(html, javascript, intelligence, report)
