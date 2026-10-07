from pydantic import BaseModel


class MalwareScanResultResponse(BaseModel):
    status: str
    prediction: str | None
    probability: float | None
    risk_score: int | None
    risk_level: str
    evidence: list[str]


class DownloadAssessmentResponse(BaseModel):
    file: dict[str, object]
    malware_result: MalwareScanResultResponse
    risk: str
    evidence: list[str]


class WebsiteDownloadReportResponse(BaseModel):
    status: str
    website_risk: str
    downloads: list[DownloadAssessmentResponse]
    evidence: list[str]
    potential_impact: list[str]
