"""Offline lexical feature extraction for URLs.

No network request, DNS lookup, reputation service, or rule-based classification is
performed here. The resulting values are inputs for a future ML model only.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import parse_qsl, urlsplit

SUSPICIOUS_KEYWORDS: tuple[str, ...] = (
    "login",
    "verify",
    "account",
    "secure",
    "bank",
    "update",
    "password",
    "signin",
    "confirm",
)

FEATURE_NAMES: tuple[str, ...] = (
    "url_length",
    "domain_length",
    "path_length",
    "query_length",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_slashes",
    "num_digits",
    "num_special_characters",
    "num_subdomains",
    "uses_https",
    "contains_ip_address",
    "contains_at_symbol",
    "contains_suspicious_port",
    "num_parameters",
    "url_entropy",
    "suspicious_keyword_count",
)

_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


def _parse_url(url: str):
    if not isinstance(url, str):
        raise ValueError("URL must be a string.")

    value = url.strip()
    if not value or any(character.isspace() for character in value):
        raise ValueError("URL is empty or contains whitespace.")

    # URL datasets frequently omit the scheme. Add one only for parsing; all
    # character-count features are still calculated from the original value.
    parse_target = value if "://" in value else f"http://{value}"
    try:
        parsed = urlsplit(parse_target)
        hostname = parsed.hostname
        _ = parsed.port  # Force validation of malformed/out-of-range ports.
    except ValueError as error:
        raise ValueError(f"Malformed URL: {error}") from error

    if parsed.scheme.lower() not in {"http", "https"} or not hostname:
        raise ValueError("URL must use HTTP(S) and contain a hostname.")

    _validate_hostname(hostname)
    return value, parsed


def _validate_hostname(hostname: str) -> None:
    candidate = hostname.rstrip(".")
    if not candidate:
        raise ValueError("URL hostname is empty.")

    try:
        ipaddress.ip_address(candidate)
        return
    except ValueError:
        pass

    try:
        ascii_hostname = candidate.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ValueError("URL hostname is not valid IDNA.") from error

    if len(ascii_hostname) > 253:
        raise ValueError("URL hostname is too long.")

    labels = ascii_hostname.split(".")
    if len(labels) < 2 or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise ValueError("URL hostname is not a valid domain or IP address.")


def is_valid_url(url: object) -> bool:
    try:
        _parse_url(url)  # type: ignore[arg-type]
        return True
    except (TypeError, ValueError):
        return False


def calculate_entropy(value: str) -> float:
    """Return Shannon entropy in bits per character."""
    if not value:
        return 0.0
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in Counter(value).values())


def _is_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname.rstrip("."))
        return True
    except ValueError:
        return False


def _count_subdomains(hostname: str) -> int:
    if _is_ip_address(hostname):
        return 0
    # Offline lexical approximation: the final two labels are treated as the
    # registrable domain and suffix. No public-suffix network lookup is made.
    return max(0, len(hostname.rstrip(".").split(".")) - 2)


def extract_url_features(url: str) -> dict[str, int | float]:
    """Extract deterministic lexical features from one valid HTTP(S) URL."""
    value, parsed = _parse_url(url)
    hostname = parsed.hostname or ""
    lowered = value.lower()
    port = parsed.port

    features: dict[str, int | float] = {
        "url_length": len(value),
        "domain_length": len(hostname),
        "path_length": len(parsed.path),
        "query_length": len(parsed.query),
        "num_dots": value.count("."),
        "num_hyphens": value.count("-"),
        "num_underscores": value.count("_"),
        "num_slashes": value.count("/"),
        "num_digits": sum(character.isdigit() for character in value),
        "num_special_characters": sum(not character.isalnum() for character in value),
        "num_subdomains": _count_subdomains(hostname),
        "uses_https": int(parsed.scheme.lower() == "https" and "://" in value),
        "contains_ip_address": int(_is_ip_address(hostname)),
        "contains_at_symbol": int("@" in value),
        "contains_suspicious_port": int(port is not None and port not in {80, 443}),
        "num_parameters": len(parse_qsl(parsed.query, keep_blank_values=True)),
        "url_entropy": round(calculate_entropy(value), 6),
        "suspicious_keyword_count": sum(lowered.count(keyword) for keyword in SUSPICIOUS_KEYWORDS),
    }
    return features

