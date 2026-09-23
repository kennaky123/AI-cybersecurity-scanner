from pydantic import BaseModel, field_validator

from ml.phishing.features import is_valid_url

from .explanation import ModelExplanationResponse


class PhishingScanRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url_without_normalizing(cls, value: str) -> str:
        preserved = value.strip()
        if not is_valid_url(preserved):
            raise ValueError("URL must be a valid HTTP(S) URL.")
        return preserved


class PhishingScanResponse(BaseModel):
    url: str
    prediction: str
    probability: float
    risk_score: int
    risk_level: str
    features: dict[str, int | float]
    reasons: list[str]
    explanation: ModelExplanationResponse
