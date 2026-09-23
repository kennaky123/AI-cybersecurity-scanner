import math

import pytest

from ml.phishing.features import FEATURE_NAMES, calculate_entropy, extract_url_features, is_valid_url


def test_extracts_expected_lexical_features() -> None:
    url = "https://login.example.com/account/verify?user=123&id=7"

    features = extract_url_features(url)

    assert tuple(features) == FEATURE_NAMES
    assert features["url_length"] == len(url)
    assert features["domain_length"] == len("login.example.com")
    assert features["path_length"] == len("/account/verify")
    assert features["query_length"] == len("user=123&id=7")
    assert features["num_dots"] == 2
    assert features["num_slashes"] == 4
    assert features["num_digits"] == 4
    assert features["num_subdomains"] == 1
    assert features["uses_https"] == 1
    assert features["contains_ip_address"] == 0
    assert features["contains_at_symbol"] == 0
    assert features["contains_suspicious_port"] == 0
    assert features["num_parameters"] == 2
    assert features["suspicious_keyword_count"] == 3


def test_detects_ip_address_at_symbol_and_nonstandard_port() -> None:
    features = extract_url_features("http://user@192.168.1.5:8080/download?empty=")

    assert features["contains_ip_address"] == 1
    assert features["contains_at_symbol"] == 1
    assert features["contains_suspicious_port"] == 1
    assert features["num_subdomains"] == 0
    assert features["num_parameters"] == 1


@pytest.mark.parametrize(
    "url",
    ["", "not-a-domain", "javascript:alert(1)", "http://bad host.test", "https://example.com:99999"],
)
def test_rejects_invalid_urls(url: str) -> None:
    assert is_valid_url(url) is False


def test_accepts_dataset_url_without_scheme() -> None:
    features = extract_url_features("example.com/login")

    assert features["uses_https"] == 0
    assert features["domain_length"] == len("example.com")
    assert features["suspicious_keyword_count"] == 1


def test_entropy() -> None:
    assert calculate_entropy("") == 0.0
    assert calculate_entropy("aaaa") == 0.0
    assert math.isclose(calculate_entropy("ab"), 1.0)

