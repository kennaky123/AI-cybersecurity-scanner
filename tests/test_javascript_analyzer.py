from backend.app.services.javascript_analyzer import JavaScriptAnalyzer


def analyze(source: str, external_scripts=None):
    return JavaScriptAnalyzer().analyze([source], external_scripts or [], "https://example.com/login")


def test_normal_javascript_has_no_suspicious_indicator() -> None:
    result = analyze("const total = 1 + 2; console.log(total);")

    assert result.javascript_score == 0
    assert result.apis == []
    assert result.suspicious_behaviors == []


def test_cookie_access_is_observed_but_not_called_cookie_stealing() -> None:
    result = analyze("const value = document.cookie;")

    assert "COOKIE_ACCESS" in result.observed_static_indicators
    assert "COOKIE_ACCESS_WITH_NETWORK_API" not in result.suspicious_behaviors
    assert any("transmission is not established" in item for item in result.potential_capabilities)


def test_storage_clipboard_fetch_and_websocket_are_separated_from_behavior() -> None:
    result = analyze("localStorage.setItem('x', '1'); navigator.clipboard.readText(); fetch('/api'); new WebSocket('wss://example.com');")

    assert "LOCAL_STORAGE_ACCESS" in result.observed_static_indicators
    assert "CLIPBOARD_ACCESS" in result.observed_static_indicators
    assert "FETCH_API" in result.observed_static_indicators
    assert "WEBSOCKET_API" in result.observed_static_indicators
    assert "CLIENT_DATA_ACCESS_WITH_NETWORK_API" in result.suspicious_behaviors


def test_obfuscated_generated_code_is_reported() -> None:
    result = analyze("eval(atob('SGVsbG8=')); const x='\\x61\\x62\\x63';")

    assert result.obfuscation["detected"] is True
    assert "EVAL_CALL" in result.observed_static_indicators
    assert "CODE_GENERATION_WITH_OBFUSCATION" in result.suspicious_behaviors


def test_dynamic_iframe_script_and_redirect_are_static_observations() -> None:
    result = analyze("const frame=document.createElement('iframe'); document.body.appendChild(frame); const s=document.createElement('script'); window.location.replace('https://example.net');", [{"url": "https://cdn.example.net/app.js", "external": True}])

    assert "DYNAMIC_IFRAME" in result.observed_static_indicators
    assert "DYNAMIC_SCRIPT_INJECTION" in result.observed_static_indicators
    assert "EXTERNAL_SCRIPT_LOADING" in result.observed_static_indicators
    assert result.redirects
    assert "REDIRECT_PATTERN" in result.observed_static_indicators
