"""Phase 1 URL and domain analysis.

This module is deterministic and offline by default. Optional DNS, ASN and
domain-age values are represented as unavailable until a trusted provider is
explicitly injected; no network lookup is performed implicitly.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit

from ml.phishing.features import (
    FEATURE_NAMES,
    SUSPICIOUS_KEYWORDS,
    calculate_entropy,
    extract_url_features,
)

SUSPICIOUS_TLDS = frozenset({"click", "country", "cf", "cam", "fit", "ga", "gq", "icu", "ml", "mov", "rest", "tk", "top", "work", "xyz", "zip"})
BRAND_DOMAINS = {
    "amazon", "apple", "bank", "facebook", "github", "google", "instagram", "linkedin",
    "microsoft", "netflix", "paypal", "siemens", "spotify", "tiktok", "twitter", "whatsapp", "youtube",
}


@dataclass(frozen=True, slots=True)
class AnalyzerResult:
    score: int
    features: dict[str, object]
    indicators: list[str] = field(default_factory=list)
    severity: str = "LOW"
    explanation: list[str] = field(default_factory=list)

    @classmethod
    def unavailable(cls, message: str = "Analysis unavailable.") -> "AnalyzerResult":
        return cls(0, {}, [], "LOW", [message])


def _severity(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def _hostname_parts(hostname: str) -> tuple[str, str, list[str]]:
    labels = hostname.rstrip(".").lower().split(".") if hostname else []
    registrable = hostname if _ip_info(hostname)[0] else (".".join(labels[-2:]) if len(labels) >= 2 else hostname)
    tld = labels[-1] if labels else ""
    return registrable, tld, labels


def _ip_info(hostname: str) -> tuple[str | None, str | None]:
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return None, None
    return str(address), f"IPv{address.version}"


class DomainAnalyzer:
    """Analyze hostname structure without DNS or reputation requests."""

    def analyze(self, url: str) -> AnalyzerResult:
        base = extract_url_features(url)
        parsed = urlsplit(url if "://" in url else f"http://{url}")
        hostname = (parsed.hostname or "").lower().rstrip(".")
        registrable, tld, labels = _hostname_parts(hostname)
        ip_address, ip_version = _ip_info(hostname)
        trusted_brand_domain = any(hostname == f"{brand}.com" or hostname.endswith(f".{brand}.com") for brand in BRAND_DOMAINS)
        brand_matches = [brand.strip() for brand in BRAND_DOMAINS if brand.strip() in labels and not trusted_brand_domain]

        indicators: list[str] = []
        explanation: list[str] = []
        score = 0
        if ip_address:
            score += 25
            indicators.append("IP_ADDRESS_INSTEAD_OF_DOMAIN")
            explanation.append("The hostname is a literal IP address, so the URL does not identify a stable organization domain.")
        if base["num_subdomains"] >= 3:
            score += 15
            indicators.append("MANY_SUBDOMAINS")
            explanation.append(f"The hostname contains {base['num_subdomains']} subdomain level(s), increasing brand-spoofing complexity.")
        if tld in SUSPICIOUS_TLDS:
            score += 15
            indicators.append("SUSPICIOUS_TLD")
            explanation.append(f"The top-level domain .{tld} is treated as higher-risk by this lexical policy; this is not proof of abuse.")
        if brand_matches:
            score += 25
            indicators.append("BRAND_IMPERSONATION_IN_DOMAIN")
            explanation.append(f"Brand-like label(s) detected outside an authoritative domain: {', '.join(brand_matches)}.")

        features = {
            "hostname": hostname,
            "hostname_length": len(hostname),
            "num_at_symbols": url.count("@"),
            "num_subdomains": int(base["num_subdomains"]),
            "registrable_domain": registrable,
            "tld": tld,
            "suspicious_tld": int(tld in SUSPICIOUS_TLDS),
            "brand_matches": brand_matches,
            "ip_address": ip_address,
            "ip_version": ip_version,
            "domain_age_days": None,
            "domain_age_status": "UNAVAILABLE_NO_PROVIDER",
            "dns_status": "UNAVAILABLE_OFFLINE_MODE",
            "dns_records": None,
            "asn": None,
            "asn_status": "UNAVAILABLE_NO_PROVIDER",
        }
        if not explanation:
            explanation.append("No domain-structure indicator crossed the configured thresholds.")
        return AnalyzerResult(min(score, 100), features, indicators, _severity(min(score, 100)), explanation)


class URLAnalyzer:
    """Analyze URL syntax and prepare the existing ML feature vector."""

    def __init__(self, domain_analyzer: DomainAnalyzer | None = None) -> None:
        self.domain_analyzer = domain_analyzer or DomainAnalyzer()

    def analyze(self, url: str) -> AnalyzerResult:
        base = extract_url_features(url)
        parsed = urlsplit(url if "://" in url else f"http://{url}")
        hostname = parsed.hostname or ""
        domain_result = self.domain_analyzer.analyze(url)
        encoded_count = url.count("%")
        decoded_changed = unquote(url) != url
        keyword_matches = sorted({keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in url.lower()})
        indicators: list[str] = []
        explanation: list[str] = []
        score = 0

        def add(condition: bool, weight: int, name: str, message: str) -> None:
            nonlocal score
            if condition:
                score += weight
                indicators.append(name)
                explanation.append(message)

        add(len(url) > 120, 10, "URL_TOO_LONG", f"The URL has {len(url)} characters; long URLs are harder for users to inspect.")
        add(len(url) > 220, 10, "URL_VERY_LONG", "The URL is exceptionally long and may hide its meaningful destination among parameters or encoded data.")
        add(base["num_subdomains"] >= 3, 10, "MANY_SUBDOMAINS", "The URL has several subdomain levels, which can make a brand-like hostname look legitimate.")
        add(bool(base["contains_at_symbol"]), 15, "AT_SYMBOL_OBFUSCATION", "The @ delimiter can make a browser display look like it belongs to a trusted host while the actual host is different.")
        add(bool(base["contains_ip_address"]), 15, "IP_BASED_URL", "The destination is addressed by IP instead of an organization domain.")
        add(encoded_count > 0 or decoded_changed, 10, "PERCENT_ENCODING", f"The URL contains {encoded_count} percent-encoding marker(s), which can hide readable content.")
        add(bool(keyword_matches), 10, "SUSPICIOUS_KEYWORDS", f"Account/security language detected: {', '.join(keyword_matches)}.")
        add(float(base["url_entropy"]) >= 4.2, 10, "HIGH_URL_ENTROPY", "The character distribution is relatively random, a possible sign of generated or obfuscated URL content.")
        add(not bool(base["uses_https"]), 5, "NO_HTTPS", "The URL does not use HTTPS, so transport confidentiality is not established.")
        if domain_result.score:
            score += min(30, domain_result.score // 2)
            indicators.extend(f"DOMAIN_{item}" for item in domain_result.indicators if f"DOMAIN_{item}" not in indicators)
            explanation.extend(domain_result.explanation)

        model_features = {name: base[name] for name in FEATURE_NAMES}
        features = {
            **model_features,
            "hostname_length": len(hostname),
            "num_at_symbols": url.count("@"),
            "percent_encoding_count": encoded_count,
            "ip_address": domain_result.features["ip_address"],
            "suspicious_keywords": keyword_matches,
            "hostname_suspicious_keywords": sorted({keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in hostname}),
            "suspicious_tld": domain_result.features["suspicious_tld"],
            "hostname_entropy": round(calculate_entropy(hostname), 6),
            "domain_age_days": None,
            "domain_age_status": "UNAVAILABLE_NO_PROVIDER",
            "dns_status": "UNAVAILABLE_OFFLINE_MODE",
            "dns_records": None,
            "asn": None,
            "asn_status": "UNAVAILABLE_NO_PROVIDER",
            "model_feature_order": list(FEATURE_NAMES),
            "model_feature_vector": [model_features[name] for name in FEATURE_NAMES],
        }
        if not explanation:
            explanation.append("No configured URL or domain indicator crossed the analysis thresholds.")
        final_score = min(score, 100)
        return AnalyzerResult(final_score, features, indicators, _severity(final_score), explanation)
