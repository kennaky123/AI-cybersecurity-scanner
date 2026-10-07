"""Evidence-grounded explanations for users learning from a scan.

These are deliberately framed as possibilities. Static features can explain why
an artifact resembles suspicious samples, but cannot prove runtime behavior.
"""

from dataclasses import dataclass, field
from typing import Mapping, Sequence


@dataclass(frozen=True, slots=True)
class SecurityEducation:
    summary: str
    evidence: list[str] = field(default_factory=list)
    possible_capabilities: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    limitation: str = ""

    @classmethod
    def unavailable(cls) -> "SecurityEducation":
        return cls(
            summary="Educational analysis is unavailable because no model result was produced.",
            limitation="This panel explains static evidence; it does not prove what code does at runtime.",
        )


def phishing_education(features: Mapping[str, int | float], prediction: str) -> SecurityEducation:
    evidence: list[str] = []
    possibilities: list[str] = []

    if features.get("contains_ip_address", 0):
        evidence.append("The URL uses an IP address instead of a recognizable domain.")
        possibilities.append("It could hide the real organization behind a hard-to-recognize address.")
    if features.get("contains_at_symbol", 0):
        evidence.append("The URL contains '@', which can make the visible part look like a trusted domain.")
        possibilities.append("It could be used for visual deception or credential harvesting.")
    if features.get("contains_suspicious_port", 0):
        evidence.append("The URL uses a non-standard or suspicious port.")
        possibilities.append("It could point to a temporary phishing service or an unusual backend.")
    if features.get("num_subdomains", 0) >= 3:
        evidence.append(f"The URL has {int(features['num_subdomains'])} subdomains, increasing its structural complexity.")
        possibilities.append("It could imitate a brand name inside a longer attacker-controlled domain.")
    if features.get("suspicious_keyword_count", 0) > 0:
        evidence.append(f"It contains {int(features['suspicious_keyword_count'])} security or account-related keyword(s).")
        possibilities.append("It could be designed to create urgency and collect login or payment information.")
    if features.get("num_parameters", 0) >= 3:
        evidence.append(f"The URL contains {int(features['num_parameters'])} query parameters.")
        possibilities.append("Parameters could be used for tracking, campaign routing or a targeted landing page.")
    if features.get("uses_https", 0) == 0:
        evidence.append("The URL does not use HTTPS.")
        possibilities.append("Data sent to the page could be exposed or modified in transit.")

    if not evidence:
        evidence.append("No strong rule-level URL signal was found; the result mainly comes from the trained model pattern.")
    if not possibilities:
        possibilities.append("The URL may still be a false positive or a previously unseen phishing pattern.")

    flagged = prediction == "PHISHING"
    return SecurityEducation(
        summary=("The URL resembles phishing examples because its lexical structure contains suspicious signals."
                 if flagged else
                 "The URL does not strongly resemble the phishing patterns learned by this model."),
        evidence=evidence,
        possible_capabilities=possibilities,
        recommended_actions=(
            ["Do not enter credentials or payment details.", "Open the organization through a saved bookmark or official app.", "Report the message or link to the organization and your mail provider."]
            if flagged else
            ["Still verify the sender and context before entering sensitive information.", "Use the official domain or app when an account action is requested."]
        ),
        limitation="The app analyzes the URL only. It does not visit the page, inspect JavaScript, verify DNS, or prove what the page does.",
    )


def malware_education(
    pe_info: Mapping[str, object], important_features: Sequence[object], prediction: str
) -> SecurityEducation:
    evidence: list[str] = []
    possibilities: list[str] = []
    entropy = float(pe_info.get("maximum_section_entropy", 0) or 0)
    imports = int(pe_info.get("number_of_imported_functions", 0) or 0)
    sections = int(pe_info.get("number_of_sections", 0) or 0)
    signature = pe_info.get("signature") if isinstance(pe_info.get("signature"), Mapping) else {}

    if entropy >= 7.0:
        evidence.append(f"A PE section has high entropy ({entropy:.2f}/8), which is consistent with packing or encryption.")
        possibilities.append("The file could be hiding its real code or configuration until runtime.")
    if sections >= 8:
        evidence.append(f"The file contains {sections} sections, an unusually complex PE layout for a small utility.")
        possibilities.append("Extra sections could carry packed code, embedded data or a second-stage payload.")
    if imports >= 150:
        evidence.append(f"The binary imports {imports} functions, giving it a broad operating-system API surface.")
        possibilities.append("Depending on the imported APIs, it could access files, processes, the network or system settings.")
    if signature.get("is_signed") is False:
        evidence.append("No Authenticode signature was found.")
        possibilities.append("The publisher identity cannot be verified from a trusted digital signature.")
    elif signature.get("has_valid_chain") is False:
        evidence.append("A signature exists, but the chain was not verified as trusted.")
        possibilities.append("The file could be self-signed, expired, or signed by an untrusted publisher.")
    if not evidence:
        evidence.append("No single static indicator explains the result; the model recognized a combination of PE features.")
    if not possibilities:
        possibilities.append("The file may be a false positive or use behavior that static analysis cannot observe.")

    flagged = prediction == "MALWARE"
    return SecurityEducation(
        summary=("The file resembles malware samples because multiple static PE signals match the trained model's patterns."
                 if flagged else
                 "The file does not strongly resemble the malware patterns learned by this model."),
        evidence=evidence,
        possible_capabilities=possibilities,
        recommended_actions=(
            ["Do not execute the file on a personal or production machine.", "Quarantine it and preserve the SHA-256 for investigation.", "If analysis is necessary, use an isolated sandbox with no sensitive data."]
            if flagged else
            ["Verify the download source and publisher before opening it.", "Keep the SHA-256 so the exact artifact can be compared later."]
        ),
        limitation="Static analysis explains suspicious structure; it cannot confirm runtime behavior, payload intent, or complete safety.",
    )
