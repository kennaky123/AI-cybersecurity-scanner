from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    score: int
    level: str


class RiskEngine:
    """Map the model's phishing probability to a display risk band."""

    @staticmethod
    def calculate(probability: float) -> RiskAssessment:
        if not 0.0 <= probability <= 1.0:
            raise ValueError("Probability must be between 0 and 1.")

        score = round(probability * 100)
        if score <= 29:
            level = "LOW"
        elif score <= 59:
            level = "MEDIUM"
        elif score <= 79:
            level = "HIGH"
        else:
            level = "CRITICAL"
        return RiskAssessment(score=score, level=level)
