"""Static JavaScript inspection for Phase 3.

Only source text and script URLs are inspected. Nothing is imported, evaluated,
rendered, or executed on the scanner host.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .html_analyzer import _host
from .url_analyzer import SUSPICIOUS_TLDS


@dataclass(frozen=True, slots=True)
class JavaScriptAnalysis:
    javascript_score: int
    apis: list[str] = field(default_factory=list)
    external_scripts: list[dict[str, object]] = field(default_factory=list)
    redirects: list[dict[str, object]] = field(default_factory=list)
    obfuscation: dict[str, object] = field(default_factory=dict)
    network_indicators: list[str] = field(default_factory=list)
    potential_capabilities: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    explanation: list[str] = field(default_factory=list)
    observed_static_indicators: list[str] = field(default_factory=list)
    suspicious_behaviors: list[str] = field(default_factory=list)


_API_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("eval()", r"\beval\s*\(", "EVAL_CALL"),
    ("Function constructor", r"(?:\bnew\s+Function\s*\(|\bFunction\s*\()", "FUNCTION_CONSTRUCTOR"),
    ("document.cookie", r"\bdocument\s*\.\s*cookie\b", "COOKIE_ACCESS"),
    ("localStorage", r"\blocalStorage\b", "LOCAL_STORAGE_ACCESS"),
    ("sessionStorage", r"\bsessionStorage\b", "SESSION_STORAGE_ACCESS"),
    ("clipboard API", r"\b(?:navigator\s*\.\s*)?clipboard\b", "CLIPBOARD_ACCESS"),
    ("navigator API", r"\bnavigator\s*\.", "NAVIGATOR_API"),
    ("fetch()", r"\bfetch\s*\(", "FETCH_API"),
    ("XMLHttpRequest", r"\bXMLHttpRequest\b", "XMLHTTPREQUEST_API"),
    ("WebSocket", r"\bWebSocket\s*\(", "WEBSOCKET_API"),
    ("window.location", r"\b(?:window\s*\.\s*)?location\s*(?:\.\s*(?:href|replace|assign)|\s*=)", "LOCATION_REDIRECT"),
    ("iframe creation", r"createElement\s*\(\s*['\"]iframe['\"]\s*\)", "DYNAMIC_IFRAME"),
    ("dynamic script injection", r"createElement\s*\(\s*['\"]script['\"]\s*\)", "DYNAMIC_SCRIPT_INJECTION"),
)

_ENDPOINT = re.compile(r"(?:https?|wss?):\/\/[^\s'\"`<>\\]+", re.IGNORECASE)
_REDIRECT = re.compile(r"(?:window\s*\.\s*location|location\s*\.\s*(?:href|replace|assign))[^;\n]{0,180}", re.IGNORECASE)
_ENCODED = re.compile(r"(?:atob|btoa|fromCharCode|unescape|decodeURIComponent)\s*\(|(?:\\x[0-9a-f]{2}){3,}|(?:\\u[0-9a-f]{4}){3,}", re.IGNORECASE)


def _suspicious_host(hostname: str) -> bool:
    labels = hostname.lower().split(".") if hostname else []
    return bool(
        hostname
        and (
            hostname.replace(".", "").isdigit()
            or labels[-1] in SUSPICIOUS_TLDS
            or any(word in hostname for word in ("login", "verify", "collect", "secure", "wallet"))
        )
    )


class JavaScriptAnalyzer:
    """Inspect JavaScript source without executing it."""

    def analyze(
        self,
        inline_scripts: list[str],
        external_scripts: list[dict[str, object]] | None = None,
        page_url: str = "",
    ) -> JavaScriptAnalysis:
        scripts = [source for source in inline_scripts if isinstance(source, str)]
        external = list(external_scripts or [])
        source = "\n".join(scripts)
        apis: list[str] = []
        observed: list[str] = []
        indicators: list[str] = []
        explanations: list[str] = []
        capabilities: list[str] = []
        suspicious_behaviors: list[str] = []
        score = 0

        matched: set[str] = set()
        for label, pattern, indicator in _API_PATTERNS:
            if re.search(pattern, source, re.IGNORECASE):
                apis.append(label)
                observed.append(indicator)
                matched.add(indicator)
                score += 5

        encoded_matches = _ENCODED.findall(source)
        long_string_count = len(re.findall(r"['\"][A-Za-z0-9+/=_-]{80,}['\"]", source))
        obfuscation = {
            "detected": bool(encoded_matches or long_string_count >= 2),
            "encoded_constructs": sorted(set(item.lower() for item in encoded_matches))[:10],
            "long_encoded_string_count": long_string_count,
        }
        if obfuscation["detected"]:
            observed.append("ENCODED_OR_OBFUSCATED_SOURCE")
            score += 10
            explanations.append("Encoded or unusually long string constructs were observed; their purpose is not established by static inspection.")

        endpoints = sorted(set(_ENDPOINT.findall(source)))
        network_indicators = []
        page_host = _host(page_url)
        for endpoint in endpoints:
            endpoint_host = _host(endpoint)
            if endpoint_host and endpoint_host != page_host:
                prefix = "SUSPICIOUS_EXTERNAL_ENDPOINT" if _suspicious_host(endpoint_host) else "EXTERNAL_ENDPOINT"
                network_indicators.append(f"{prefix}:{endpoint_host}")
                if prefix == "SUSPICIOUS_EXTERNAL_ENDPOINT":
                    observed.append("SUSPICIOUS_NETWORK_ENDPOINT")
                    indicators.append("SUSPICIOUS_NETWORK_ENDPOINT")
                    score += 10
            else:
                network_indicators.append(f"NETWORK_ENDPOINT:{endpoint_host or 'unknown'}")
        if external:
            normalized_external: list[dict[str, object]] = []
            for item in external:
                item_copy = dict(item)
                item_copy["suspicious_domain"] = _suspicious_host(_host(str(item_copy.get("url", ""))))
                normalized_external.append(item_copy)
            external = normalized_external
            observed.append("EXTERNAL_SCRIPT_LOADING")
            score += min(10, len(external) * 3)
            explanations.append("The page references external JavaScript; the referenced code was not downloaded or executed in this analysis.")
            if any(item.get("suspicious_domain") for item in external):
                observed.append("SUSPICIOUS_EXTERNAL_SCRIPT_DOMAIN")
                indicators.append("SUSPICIOUS_EXTERNAL_SCRIPT_DOMAIN")
                score += 10
                explanations.append("At least one external script URL has a suspicious IP, TLD, or hostname pattern.")

        redirects = [{"type": "location", "snippet": match.strip()[:220]} for match in _REDIRECT.findall(source)[:10]]
        if redirects:
            observed.append("REDIRECT_PATTERN")
            score += 10
            capabilities.append("May redirect the browser to another location; the destination and intent require further review.")

        capability_map = {
            "COOKIE_ACCESS": "May read browser cookies; transmission is not established.",
            "LOCAL_STORAGE_ACCESS": "May read or write localStorage data.",
            "SESSION_STORAGE_ACCESS": "May read or write sessionStorage data.",
            "CLIPBOARD_ACCESS": "May read or write clipboard content when browser permissions allow it.",
            "NAVIGATOR_API": "May inspect browser or device-related navigator properties.",
            "FETCH_API": "May make HTTP requests from the browser context.",
            "XMLHTTPREQUEST_API": "May make asynchronous HTTP requests from the browser context.",
            "WEBSOCKET_API": "May open a persistent network channel from the browser context.",
            "DYNAMIC_IFRAME": "May create an iframe dynamically and load additional content.",
            "DYNAMIC_SCRIPT_INJECTION": "May load or execute additional script after page load.",
            "EVAL_CALL": "May evaluate generated code, making intent harder to inspect statically.",
            "FUNCTION_CONSTRUCTOR": "May construct generated code, making intent harder to inspect statically.",
        }
        for indicator in matched:
            if indicator in capability_map:
                capabilities.append(capability_map[indicator])

        network_api_present = bool(matched & {"FETCH_API", "XMLHTTPREQUEST_API", "WEBSOCKET_API"})
        storage_or_cookie = bool(matched & {"COOKIE_ACCESS", "LOCAL_STORAGE_ACCESS", "SESSION_STORAGE_ACCESS", "CLIPBOARD_ACCESS"})
        if "COOKIE_ACCESS" in matched and network_api_present:
            suspicious_behaviors.append("COOKIE_ACCESS_WITH_NETWORK_API")
            indicators.append("COOKIE_ACCESS_WITH_NETWORK_API")
            score += 20
            explanations.append("JavaScript accesses document.cookie and also contains a network API; whether cookies are transmitted is not proven.")
        if storage_or_cookie and network_api_present and "COOKIE_ACCESS_WITH_NETWORK_API" not in suspicious_behaviors:
            suspicious_behaviors.append("CLIENT_DATA_ACCESS_WITH_NETWORK_API")
            indicators.append("CLIENT_DATA_ACCESS_WITH_NETWORK_API")
            score += 15
            explanations.append("Client-side data access appears alongside a network API; static analysis cannot confirm what data is sent.")
        if ("EVAL_CALL" in matched or "FUNCTION_CONSTRUCTOR" in matched) and obfuscation["detected"]:
            suspicious_behaviors.append("CODE_GENERATION_WITH_OBFUSCATION")
            indicators.append("CODE_GENERATION_WITH_OBFUSCATION")
            score += 20
            explanations.append("Generated-code APIs and encoded constructs occur together, which makes the source harder to audit.")
        if endpoints:
            explanations.append(f"{len(endpoints)} network endpoint(s) were found in source text; an endpoint alone does not prove malicious behavior.")

        if not explanations:
            explanations.append("No configured static JavaScript indicator was observed.")
        explanations.append("These are static observations and potential capabilities, not proof that the website is malware or steals data.")
        return JavaScriptAnalysis(
            javascript_score=min(score, 100),
            apis=apis,
            external_scripts=external,
            redirects=redirects,
            obfuscation=obfuscation,
            network_indicators=network_indicators,
            potential_capabilities=sorted(set(capabilities)),
            indicators=sorted(set(indicators)),
            explanation=explanations,
            observed_static_indicators=sorted(set(observed)),
            suspicious_behaviors=sorted(set(suspicious_behaviors)),
        )
