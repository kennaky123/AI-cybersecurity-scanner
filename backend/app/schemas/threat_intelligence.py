from typing import Literal

from pydantic import BaseModel, field_validator


ThreatType = Literal["URL", "DOMAIN", "IP", "FILE_HASH"]


class ThreatIntelLookupRequest(BaseModel):
    indicator_type: ThreatType
    value: str

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned or len(cleaned) > 4096:
            raise ValueError("Threat-intelligence indicator must be non-empty and at most 4096 characters.")
        return cleaned


class ThreatIntelResultResponse(BaseModel):
    provider: str
    status: Literal["found", "not_found", "unavailable", "error"]
    confidence: float
    categories: list[str]
    first_seen: str | None
    last_seen: str | None
    evidence: list[str]


class ThreatIntelLookupResponse(BaseModel):
    indicator_type: ThreatType
    value: str
    results: list[ThreatIntelResultResponse]
