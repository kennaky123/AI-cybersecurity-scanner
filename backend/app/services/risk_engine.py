from dataclasses import asdict, dataclass, field
from typing import Any, Mapping, Sequence


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    score: int
    level: str


@dataclass(frozen=True, slots=True)
class RiskEvidence:
    category: str
    indicator: str
    severity: str
    observed_value: str
    explanation: str


@dataclass(frozen=True, slots=True)
class RiskReport:
    risk_score: int
    classification: str
    confidence: float
    severity: str
    evidence: list[RiskEvidence] = field(default_factory=list)
    potential_impact: list[str] = field(default_factory=list)
    observed_behavior: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    @classmethod
    def unavailable(cls) -> "RiskReport":
        return cls(0, "SAFE", 0.0, "LOW", recommendations=["No aggregate risk report was produced."])


class RiskEngine:
    """Aggregate independent evidence without treating one signal as proof."""

    def __init__(self, *, suspicious_threshold: int = 30, phishing_threshold: int = 60) -> None:
        if not 0 <= suspicious_threshold < phishing_threshold <= 100:
            raise ValueError("Risk thresholds must satisfy 0 <= suspicious < phishing <= 100.")
        self.suspicious_threshold = suspicious_threshold
        self.phishing_threshold = phishing_threshold

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

    @staticmethod
    def _value(value: object) -> str:
        if value is None:
            return "unknown"
        if isinstance(value, (dict, list, tuple)):
            return str(value)
        return str(value)

    @staticmethod
    def _mapping(value: object) -> Mapping[str, Any]:
        if isinstance(value, Mapping):
            return value
        try:
            converted = asdict(value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return {}
        return converted if isinstance(converted, Mapping) else {}

    @staticmethod
    def _severity(score: int) -> str:
        if score >= 80:
            return "CRITICAL"
        if score >= 60:
            return "HIGH"
        if score >= 30:
            return "MEDIUM"
        return "LOW"

    def assess(
        self,
        *,
        url_analysis: object,
        domain_analysis: object,
        html_analysis: object,
        javascript_analysis: object,
        threat_intelligence: Sequence[object],
        model_probability: float | None = None,
    ) -> RiskReport:
        sources = {
            "URL": self._mapping(url_analysis),
            "DOMAIN": self._mapping(domain_analysis),
            "HTML": self._mapping(html_analysis),
            "JAVASCRIPT": self._mapping(javascript_analysis),
        }
        score = 0.0
        evidence: list[RiskEvidence] = []
        potential_impact: list[str] = []
        observed_behavior: list[str] = []

        # These weights intentionally cap each source. They provide a
        # configurable triage score, not a scientifically calibrated probability.
        source_weights = {"URL": 0.15, "DOMAIN": 0.15, "HTML": 0.20, "JAVASCRIPT": 0.15}
        for source_name, payload in sources.items():
            raw_score = float(payload.get("score", payload.get("html_score", payload.get("javascript_score", 0))) or 0)
            score += min(max(raw_score, 0.0), 100.0) * source_weights[source_name]
            indicators = payload.get("indicators", [])
            explanations = payload.get("explanation", [])
            if source_name == "JAVASCRIPT":
                indicators = [*payload.get("observed_static_indicators", []), *payload.get("suspicious_behaviors", [])]
                potential_impact.extend(str(item) for item in payload.get("potential_capabilities", []))
                observed_behavior.extend(str(item) for item in payload.get("suspicious_behaviors", []))
            if not isinstance(indicators, (list, tuple)):
                indicators = []
            if not isinstance(explanations, (list, tuple)):
                explanations = []
            for index, indicator in enumerate(indicators[:12]):
                explanation = str(explanations[index]) if index < len(explanations) else f"Observed by {source_name.lower()} analysis."
                evidence.append(RiskEvidence("OBSERVED", str(indicator), self._severity(int(raw_score)), self._value(payload.get("features", {})), explanation))

        for payload in sources.values():
            if isinstance(payload.get("potential_capabilities"), (list, tuple)):
                potential_impact.extend(str(item) for item in payload["potential_capabilities"])
        html_payload = sources["HTML"]
        if html_payload.get("credential_fields"):
            potential_impact.append("The page may collect user-entered credentials or sensitive form data.")
        if html_payload.get("external_submissions"):
            observed_behavior.append("A form submits to a domain different from the page domain.")

        threat_confidences: list[float] = []
        for raw_result in threat_intelligence:
            result = self._mapping(raw_result)
            status = result.get("status")
            if status == "found":
                confidence = min(max(float(result.get("confidence", 0) or 0), 0), 1)
                threat_confidences.append(confidence)
                score += 25.0 * confidence
                categories = result.get("categories", [])
                evidence.append(RiskEvidence("THREAT_INTELLIGENCE", f"{result.get('provider', 'provider')}:{','.join(map(str, categories))}", "CRITICAL" if confidence >= 0.8 else "HIGH", "found", "Provider reported a matching threat record; this is external intelligence, not a local behavioral proof."))
            elif status == "error":
                evidence.append(RiskEvidence("THREAT_INTELLIGENCE", f"{result.get('provider', 'provider')}:error", "LOW", "error", "Provider failed; no safety conclusion is drawn from the failure."))

        model_confidence = 0.0
        if model_probability is not None:
            probability = min(max(float(model_probability), 0.0), 1.0)
            score += probability * 15.0
            model_confidence = abs(probability - 0.5) * 2
            evidence.append(RiskEvidence("MODEL_PREDICTION", "PHISHING_PROBABILITY", self._severity(round(probability * 100)), f"{probability:.4f}", f"The existing ML model predicts phishing probability {probability:.2f}; this is a model output, not a confirmed fact."))

        final_score = min(100, max(0, round(score)))
        if final_score >= self.phishing_threshold:
            classification = "PHISHING"
        elif final_score >= self.suspicious_threshold:
            classification = "SUSPICIOUS"
        else:
            classification = "SAFE"
        signal_strength = min(1.0, final_score / 100)
        ti_confidence = max(threat_confidences, default=0.0)
        confidence = round(min(1.0, 0.35 * signal_strength + 0.35 * model_confidence + 0.30 * ti_confidence), 3)
        if classification == "PHISHING":
            recommendations = ["Do not enter credentials or payment information.", "Verify the domain through an independent trusted channel.", "Report the URL and preserve provider evidence for investigation."]
        elif classification == "SUSPICIOUS":
            recommendations = ["Do not submit sensitive information until the domain and form destination are verified.", "Review the evidence categories and check the URL with an authorized security service."]
        else:
            recommendations = ["No strong aggregate signal was observed; continue normal safe-browsing practices.", "A SAFE classification is not a guarantee of safety."]
        return RiskReport(final_score, classification, confidence, self._severity(final_score), evidence, sorted(set(potential_impact)), sorted(set(observed_behavior)), recommendations)
