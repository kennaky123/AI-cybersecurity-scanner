from __future__ import annotations

from pydantic import BaseModel, field_validator

from ml.phishing.features import is_valid_url

from .explanation import ModelExplanationResponse, SecurityEducationResponse
from .threat_intelligence import ThreatIntelResultResponse


class AnalyzerResultResponse(BaseModel):
    score: int
    features: dict[str, object]
    indicators: list[str]
    severity: str
    explanation: list[str]


class PhishingScanRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url_without_normalizing(cls, value: str) -> str:
        preserved = value.strip()
        if not is_valid_url(preserved):
            raise ValueError("URL must be a valid HTTP(S) URL.")
        return preserved


class HTMLAnalysisResponse(BaseModel):
    url: str
    final_url: str
    html_score: int
    forms: list[dict[str, object]]
    credential_fields: list[dict[str, object]]
    external_submissions: list[dict[str, object]]
    iframes: list[dict[str, object]]
    external_resources: list[dict[str, object]]
    external_scripts: list[dict[str, object]]
    indicators: list[str]
    explanation: list[str]
    status: str
    http_status: int | None
    content_type: str | None


class JavaScriptAnalysisResponse(BaseModel):
    url: str
    final_url: str
    javascript_score: int
    apis: list[str]
    external_scripts: list[dict[str, object]]
    redirects: list[dict[str, object]]
    obfuscation: dict[str, object]
    network_indicators: list[str]
    potential_capabilities: list[str]
    indicators: list[str]
    explanation: list[str]
    observed_static_indicators: list[str]
    suspicious_behaviors: list[str]


class RiskEvidenceResponse(BaseModel):
    category: str
    indicator: str
    severity: str
    observed_value: str
    explanation: str


class RiskReportResponse(BaseModel):
    risk_score: int
    classification: str
    confidence: float
    severity: str
    evidence: list[RiskEvidenceResponse]
    potential_impact: list[str]
    observed_behavior: list[str]
    recommendations: list[str]


class PhishingScanResponse(BaseModel):
    url: str
    prediction: str
    probability: float
    risk_score: int
    risk_level: str
    features: dict[str, int | float]
    reasons: list[str]
    explanation: ModelExplanationResponse
    education: SecurityEducationResponse
    url_analysis: AnalyzerResultResponse
    domain_analysis: AnalyzerResultResponse
    html_analysis: HTMLAnalysisResponse
    javascript_analysis: JavaScriptAnalysisResponse
    threat_intelligence: list[ThreatIntelResultResponse]
    risk_report: RiskReportResponse
    ai_explanation: dict[str, object] | None = None


class AIExplainRequest(BaseModel):
    scan_data: dict[str, object]
    api_key: str | None = None


class PhishingUrlAnalysisResponse(BaseModel):
    url: str
    url_analysis: AnalyzerResultResponse
    domain_analysis: AnalyzerResultResponse

