"""Safe Phase 2 HTML/form analysis.

The analyzer parses downloaded HTML only. It never executes JavaScript, submits
forms, follows redirects, or loads embedded resources. Network access is kept
behind a small fetch boundary so unit tests can inject HTML without a network.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Callable
from urllib.parse import urljoin, urlsplit

import httpx

from ml.phishing.features import is_valid_url

MAX_HTML_BYTES = 2 * 1024 * 1024
FETCH_TIMEOUT_SECONDS = 8.0
_SUSPICIOUS_LINK_WORDS = ("login", "verify", "account", "secure", "update", "password", "wallet", "payment")
_JS_REDIRECT = re.compile(r"(?:window\s*\.\s*location|location\s*\.\s*(?:href|replace|assign))\s*", re.IGNORECASE)
_BLOCKED_HOSTNAMES = frozenset({
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata.google.com",
    "instance-data.ec2.internal",
    "instance-data.ec2.internal.",
})


class HTMLFetchError(RuntimeError):
    def __init__(self, message: str, status_code: int = 502) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class FetchedHTML:
    html: str
    final_url: str
    status_code: int
    content_type: str


@dataclass(frozen=True, slots=True)
class HTMLAnalysis:
    html_score: int
    final_url: str
    forms: list[dict[str, object]] = field(default_factory=list)
    credential_fields: list[dict[str, object]] = field(default_factory=list)
    external_submissions: list[dict[str, object]] = field(default_factory=list)
    iframes: list[dict[str, object]] = field(default_factory=list)
    external_resources: list[dict[str, object]] = field(default_factory=list)
    inline_scripts: list[str] = field(default_factory=list)
    external_scripts: list[dict[str, object]] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    explanation: list[str] = field(default_factory=list)
    status: str = "FETCHED"
    http_status: int | None = None
    content_type: str | None = None


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower().rstrip(".")


def _is_private_address(address: str) -> bool:
    value = ipaddress.ip_address(address)
    return any((not value.is_global, value.is_private, value.is_loopback, value.is_link_local, value.is_multicast, value.is_reserved, value.is_unspecified))


def _resolve_public(hostname: str, port: int) -> frozenset[str]:
    normalized = hostname.lower().rstrip(".")
    if normalized in _BLOCKED_HOSTNAMES:
        raise HTMLFetchError("Target hostname is blocked by SSRF policy.", 403)
    try:
        records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise HTMLFetchError(f"DNS resolution failed for {hostname}.", 502) from error
    addresses = {record[4][0] for record in records}
    if not addresses:
        raise HTMLFetchError(f"No address found for {hostname}.", 502)
    if any(_is_private_address(address) for address in addresses):
        raise HTMLFetchError("Target resolves to a private or local network address.", 403)
    return frozenset(addresses)


def _hidden(attrs: dict[str, str | None]) -> bool:
    style = (attrs.get("style") or "").replace(" ", "").lower()
    return "hidden" in attrs or any(token in style for token in ("display:none", "visibility:hidden", "opacity:0", "width:0", "height:0"))


def _absolute(url: str, base_url: str) -> str:
    return urljoin(base_url, url.strip())


class _HTMLCollector(HTMLParser):
    def __init__(self, page_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.page_host = _host(page_url)
        self.forms: list[dict[str, object]] = []
        self.credential_fields: list[dict[str, object]] = []
        self.external_submissions: list[dict[str, object]] = []
        self.iframes: list[dict[str, object]] = []
        self.external_resources: list[dict[str, object]] = []
        self.external_scripts: list[dict[str, object]] = []
        self.hidden_elements: list[dict[str, object]] = []
        self.suspicious_links: list[dict[str, object]] = []
        self.meta_refreshes: list[str] = []
        self.script_text: list[str] = []
        self._form: dict[str, object] | None = None
        self._script_depth = 0
        self._script_buffer: list[str] = []
        self._script_external = False

    @staticmethod
    def _field_kind(attrs: dict[str, str | None]) -> str | None:
        value = " ".join((attrs.get(key) or "").lower() for key in ("type", "name", "id", "autocomplete", "placeholder", "aria-label"))
        input_type = (attrs.get("type") or "text").lower()
        if input_type == "password" or "password" in value:
            return "password"
        if input_type == "email" or "email" in value:
            return "email"
        if any(token in value for token in ("credit-card", "credit_card", "card-number", "cardnumber", "cc-number", "cvv", "cvc", "payment")):
            return "payment"
        if any(token in value for token in ("otp", "one-time", "one_time", "verification-code", "verification_code")):
            return "otp"
        if input_type == "tel" or any(token in value for token in ("phone", "mobile", "telephone")):
            return "phone"
        if any(token in value for token in ("username", "user-name", "userid", "user_id", "login")):
            return "username"
        return None

    def handle_starttag(self, tag: str, attrs_list: list[tuple[str, str | None]]) -> None:
        attrs = dict(attrs_list)
        tag = tag.lower()
        if _hidden(attrs) and len(self.hidden_elements) < 100:
            self.hidden_elements.append({"tag": tag, "id": attrs.get("id"), "class": attrs.get("class")})
        if tag == "form":
            action = _absolute(attrs.get("action") or self.page_url, self.page_url)
            submission_host = _host(action)
            self._form = {
                "index": len(self.forms),
                "action": action,
                "method": (attrs.get("method") or "get").upper(),
                "submission_domain": submission_host,
                "external_submission": bool(submission_host and submission_host != self.page_host),
                "fields": [],
            }
            if self._form["external_submission"]:
                self.external_submissions.append({"form_index": self._form["index"], "action": action, "submission_domain": submission_host, "method": self._form["method"]})
        elif tag == "input":
            kind = self._field_kind(attrs)
            if kind:
                field = {"type": kind, "name": attrs.get("name") or attrs.get("id"), "form_index": self._form["index"] if self._form else None}
                self.credential_fields.append(field)
                if self._form is not None:
                    self._form["fields"].append(field)
        elif tag == "iframe":
            source = _absolute(attrs.get("src") or "", self.page_url)
            item = {"src": source, "hidden": _hidden(attrs), "external": bool(_host(source) and _host(source) != self.page_host)}
            self.iframes.append(item)
            if item["external"]:
                self.external_resources.append({"tag": "iframe", "url": source, "external": True})
        elif tag in {"script", "link", "img", "object", "video", "audio", "source"}:
            attr_name = "data" if tag == "object" else ("href" if tag == "link" else "src")
            resource = attrs.get(attr_name)
            if resource:
                absolute = _absolute(resource, self.page_url)
                if _host(absolute) and _host(absolute) != self.page_host:
                    self.external_resources.append({"tag": tag, "url": absolute, "external": True})
            if tag == "script":
                self._script_buffer = []
                self._script_external = bool(resource)
                if resource:
                    self.external_scripts.append({"url": _absolute(resource, self.page_url), "external": _host(_absolute(resource, self.page_url)) != self.page_host})
                self._script_depth += 1
        elif tag == "a":
            href = attrs.get("href")
            if href:
                absolute = _absolute(href, self.page_url)
                lowered = absolute.lower()
                if any(word in lowered for word in _SUSPICIOUS_LINK_WORDS):
                    self.suspicious_links.append({"href": absolute, "external": _host(absolute) != self.page_host})
        elif tag == "meta" and (attrs.get("http-equiv") or "").lower() == "refresh":
            self.meta_refreshes.append(attrs.get("content") or "")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None
        elif tag == "script" and self._script_depth:
            if not self._script_external and self._script_buffer:
                self.script_text.append("".join(self._script_buffer))
            self._script_buffer = []
            self._script_external = False
            self._script_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._script_depth and data.strip():
            if not self._script_external:
                self._script_buffer.append(data)


class HTMLAnalyzer:
    def __init__(self, fetcher: Callable[[str], FetchedHTML] | None = None) -> None:
        self._fetcher = fetcher or self.fetch

    @staticmethod
    def fetch(url: str) -> FetchedHTML:
        if not is_valid_url(url):
            raise HTMLFetchError("URL must be a valid HTTP(S) URL.", 422)
        parsed = urlsplit(url)
        if parsed.username or parsed.password:
            raise HTMLFetchError("URLs containing embedded credentials are not allowed.", 400)
        hostname = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        resolved_addresses = _resolve_public(hostname, port)
        # Re-resolve immediately before connecting. This rejects common DNS
        # rebinding attempts; a production provider should still pin DNS in
        # its isolated network layer.
        if _resolve_public(hostname, port) != resolved_addresses:
            raise HTMLFetchError("DNS resolution changed during SSRF validation.", 403)
        try:
            with httpx.Client(timeout=FETCH_TIMEOUT_SECONDS, follow_redirects=False, trust_env=False, headers={"User-Agent": "AI-Security-Scanner/phase2"}) as client:
                with client.stream("GET", url) as response:
                    if 300 <= response.status_code < 400:
                        raise HTMLFetchError("Redirect was not followed during safe HTML analysis.", 502)
                    if response.status_code >= 400:
                        raise HTMLFetchError(f"Website returned HTTP {response.status_code}.", 502)
                    chunks: list[bytes] = []
                    total = 0
                    for chunk in response.iter_bytes():
                        total += len(chunk)
                        if total > MAX_HTML_BYTES:
                            raise HTMLFetchError("HTML response exceeds the 2 MB analysis limit.", 413)
                        chunks.append(chunk)
                    content_type = response.headers.get("content-type", "")
                    encoding = response.encoding or "utf-8"
                    return FetchedHTML(b"".join(chunks).decode(encoding, errors="replace"), str(response.url), response.status_code, content_type)
        except HTMLFetchError:
            raise
        except httpx.TimeoutException as error:
            raise HTMLFetchError("Website request timed out.", 408) from error
        except httpx.HTTPError as error:
            raise HTMLFetchError("Could not connect to the website.", 502) from error

    def analyze_url(self, url: str) -> HTMLAnalysis:
        fetched = self._fetcher(url)
        return self.analyze_html(fetched.html, fetched.final_url, fetched.status_code, fetched.content_type)

    @staticmethod
    def analyze_html(html: str, page_url: str, status_code: int = 200, content_type: str = "text/html") -> HTMLAnalysis:
        collector = _HTMLCollector(page_url)
        try:
            collector.feed(html)
            collector.close()
        except Exception as error:
            # HTMLParser is intentionally tolerant; preserve a useful result if
            # malformed markup triggers a parser-level error.
            collector.script_text.append(f"parser-error: {error}")

        indicators: list[str] = []
        explanation: list[str] = []
        score = 0

        def add(condition: bool, weight: int, indicator: str, message: str) -> None:
            nonlocal score
            if condition:
                score += weight
                indicators.append(indicator)
                explanation.append(message)

        password = [field for field in collector.credential_fields if field["type"] == "password"]
        login_like = bool(password or any(field["type"] in {"username", "email"} for field in collector.credential_fields))
        add(login_like, 5, "LOGIN_FORM_PRESENT", "A login-like field set exists; legitimate websites commonly have this too.")
        add(bool(password), 8, "PASSWORD_FIELD_PRESENT", "A password input can collect credentials if the user submits the form.")
        add(bool(collector.external_submissions), 40, "EXTERNAL_FORM_SUBMISSION", "Credential form submits data to an external domain.")
        add(any(item["hidden"] for item in collector.iframes), 15, "HIDDEN_IFRAME", "A hidden iframe can load content outside the visible page and deserves review.")
        add(bool(collector.external_resources), 5, "EXTERNAL_RESOURCES", "The page loads resources from other domains; this is common but reduces provenance clarity.")
        add(bool(collector.suspicious_links), 5, "SUSPICIOUS_LINKS", "Links contain account, verification, payment or security-related language.")
        add(bool(collector.meta_refreshes), 10, "META_REFRESH", "The page contains a meta refresh that can redirect the browser.")
        add(any(_JS_REDIRECT.search(script) for script in collector.script_text), 10, "JAVASCRIPT_REDIRECT", "Inline JavaScript contains a location redirect pattern.")
        add(any(field["type"] == "payment" for field in collector.credential_fields), 12, "PAYMENT_FIELD_PRESENT", "A payment-related input may collect card or payment information.")
        add(any(field["type"] == "otp" for field in collector.credential_fields), 8, "OTP_FIELD_PRESENT", "An OTP input may collect a one-time verification code.")

        explanation.append("The HTML score combines multiple signals; a login form alone is not evidence that a website is phishing.")
        return HTMLAnalysis(
            html_score=min(score, 100),
            final_url=page_url,
            forms=collector.forms,
            credential_fields=collector.credential_fields,
            external_submissions=collector.external_submissions,
            iframes=collector.iframes,
            external_resources=collector.external_resources,
            inline_scripts=collector.script_text,
            external_scripts=collector.external_scripts,
            indicators=indicators,
            explanation=explanation,
            http_status=status_code,
            content_type=content_type,
        )
