from dataclasses import dataclass
from datetime import datetime


@dataclass(slots=True)
class Scan:
    id: int | None
    scan_type: str
    target: str
    sha256: str | None
    prediction: str
    probability: float
    risk_score: int
    risk_level: str
    created_at: datetime | None = None
