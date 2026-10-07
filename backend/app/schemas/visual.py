from pydantic import BaseModel


class VisualEvidenceResponse(BaseModel):
    category: str
    indicator: str
    severity: str
    observed_value: str
    explanation: str


class VisualAnalysisResponse(BaseModel):
    status: str
    detected_brand: str | None
    logo_detected: bool
    ocr_text: list[str]
    login_page_detected: bool
    visual_similarity: float
    layout_similarity: float
    domain_matches_brand: bool | None
    brand_impersonation: bool
    evidence: list[VisualEvidenceResponse]
    explanation: list[str]
