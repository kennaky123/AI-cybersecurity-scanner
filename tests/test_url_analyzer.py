import pytest

from backend.app.services.url_analyzer import DomainAnalyzer, URLAnalyzer


def test_legitimate_url_has_model_vector_and_unknown_enrichment() -> None:
    result = URLAnalyzer().analyze("https://www.example.com/about")

    assert result.features["model_feature_order"]
    assert len(result.features["model_feature_vector"]) == 18
    assert result.features["domain_age_days"] is None
    assert result.features["dns_status"] == "UNAVAILABLE_OFFLINE_MODE"
    assert result.features["asn"] is None
    assert result.score < 30


def test_suspicious_url_accumulates_multiple_indicators() -> None:
    url = "http://login.facebook.com.scam-verification.xyz/%6cogin?account=1&verify=2&next=" + ("x" * 230)
    result = URLAnalyzer().analyze(url)

    assert result.score >= 60
    assert result.severity in {"HIGH", "CRITICAL"}
    assert "URL_TOO_LONG" in result.indicators
    assert "PERCENT_ENCODING" in result.indicators
    assert "DOMAIN_BRAND_IMPERSONATION_IN_DOMAIN" in result.indicators
    assert result.features["hostname_suspicious_keywords"] == ["login"]


def test_malformed_url_is_rejected() -> None:
    with pytest.raises(ValueError):
        URLAnalyzer().analyze("https://bad host.test/login")


def test_ip_url_is_not_treated_as_a_domain() -> None:
    result = DomainAnalyzer().analyze("http://192.168.1.5:8080/login")

    assert result.features["ip_address"] == "192.168.1.5"
    assert result.features["ip_version"] == "IPv4"
    assert result.features["registrable_domain"] == "192.168.1.5"
    assert "IP_ADDRESS_INSTEAD_OF_DOMAIN" in result.indicators


def test_long_query_is_reported_without_network_lookup() -> None:
    result = URLAnalyzer().analyze("https://example.com/search?query=" + ("a" * 180))

    assert result.features["query_length"] > 150
    assert result.features["dns_records"] is None
    assert result.features["domain_age_status"] == "UNAVAILABLE_NO_PROVIDER"
