"""Browser sandbox abstraction for Phase 6.

No browser is launched by the default implementation. A real provider must
run in an isolated container/VM with an ephemeral profile and explicit network
policy before it is enabled in production.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol, Sequence
from urllib.parse import urlsplit

from ml.phishing.features import is_valid_url


@dataclass(frozen=True, slots=True)
class SandboxPolicy:
    timeout_seconds: float = 15.0
    max_events: int = 1000
    max_download_bytes: int = 10 * 1024 * 1024
    filesystem_access: bool = False
    host_credentials: bool = False
    real_browser_profile: bool = False
    clipboard_access: bool = False
    shared_folders: bool = False


@dataclass(frozen=True, slots=True)
class TelemetryEvent:
    timestamp: str
    event_type: str
    source: str
    destination: str | None = None
    details: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SandboxDownload:
    url: str
    filename: str | None
    mime: str | None
    size: int | None
    sha256: str | None
    execution_blocked: bool = True
    content_bytes: bytes | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class ScreenshotArtifact:
    url: str
    mime: str
    width: int | None
    height: int | None
    sha256: str
    image_bytes: bytes | None = field(default=None, repr=False, compare=False)

    @classmethod
    def from_bytes(cls, url: str, image_bytes: bytes, *, mime: str = "image/png", width: int | None = None, height: int | None = None) -> "ScreenshotArtifact":
        return cls(url, mime, width, height, hashlib.sha256(image_bytes).hexdigest(), image_bytes)


@dataclass(frozen=True, slots=True)
class SandboxAnalysis:
    status: str
    url: str
    redirect_chain: list[dict[str, object]] = field(default_factory=list)
    telemetry: list[TelemetryEvent] = field(default_factory=list)
    downloads: list[SandboxDownload] = field(default_factory=list)
    external_domains: list[str] = field(default_factory=list)
    events: list[TelemetryEvent] = field(default_factory=list)
    screenshots: list[ScreenshotArtifact] = field(default_factory=list)
    policy: dict[str, object] = field(default_factory=dict)
    explanation: list[str] = field(default_factory=list)


class SandboxUnavailableError(RuntimeError):
    pass


class SandboxTimeoutError(RuntimeError):
    pass


class SandboxProvider(Protocol):
    """Provider contract; implementation owns container/VM isolation."""

    def launch(self, policy: SandboxPolicy) -> None:
        ...

    def navigate(self, url: str, timeout_seconds: float) -> None:
        ...

    def collect_network(self) -> Sequence[TelemetryEvent]:
        ...

    def collect_downloads(self) -> Sequence[SandboxDownload]:
        ...

    def collect_events(self) -> Sequence[TelemetryEvent]:
        ...

    def collect_screenshots(self) -> Sequence[ScreenshotArtifact]:
        ...

    def shutdown(self) -> None:
        ...


class UnavailableSandboxProvider:
    reason = "No isolated browser/container provider is configured."

    def launch(self, policy: SandboxPolicy) -> None:
        raise SandboxUnavailableError(self.reason)

    def navigate(self, url: str, timeout_seconds: float) -> None:
        raise SandboxUnavailableError(self.reason)

    def collect_network(self) -> Sequence[TelemetryEvent]:
        return []

    def collect_downloads(self) -> Sequence[SandboxDownload]:
        return []

    def collect_events(self) -> Sequence[TelemetryEvent]:
        return []

    def collect_screenshots(self) -> Sequence[ScreenshotArtifact]:
        return []

    def shutdown(self) -> None:
        return None


class MockSandboxProvider:
    """Deterministic safe provider for tests; it never launches a browser."""

    def __init__(
        self,
        *,
        network: Sequence[TelemetryEvent] = (),
        downloads: Sequence[SandboxDownload] = (),
        events: Sequence[TelemetryEvent] = (),
        screenshots: Sequence[ScreenshotArtifact] = (),
        error: Exception | None = None,
    ) -> None:
        self.network = list(network)
        self.downloads = list(downloads)
        self.events = list(events)
        self.screenshots = list(screenshots)
        self.error = error
        self.launched = False
        self.shutdown_called = False

    def launch(self, policy: SandboxPolicy) -> None:
        self.launched = True
        if self.error:
            raise self.error

    def navigate(self, url: str, timeout_seconds: float) -> None:
        if self.error:
            raise self.error

    def collect_network(self) -> Sequence[TelemetryEvent]:
        return self.network

    def collect_downloads(self) -> Sequence[SandboxDownload]:
        return self.downloads

    def collect_events(self) -> Sequence[TelemetryEvent]:
        return self.events

    def collect_screenshots(self) -> Sequence[ScreenshotArtifact]:
        return self.screenshots

    def shutdown(self) -> None:
        self.shutdown_called = True


class PlaywrightSandboxProvider:
    def __init__(self, headless: bool = True) -> None:
        self.headless = headless
        self._browser = None
        self._playwright = None
        self._page = None
        self._network: list[TelemetryEvent] = []
        self._downloads: list[SandboxDownload] = []
        self._events: list[TelemetryEvent] = []
        self._screenshots: list[ScreenshotArtifact] = []

    def launch(self, policy: SandboxPolicy) -> None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as e:
            raise SandboxUnavailableError("Playwright is not installed") from e
        self._playwright = sync_playwright().start()
        self._browser = self._playwright.chromium.launch(
            headless=self.headless,
            args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"]
        )
        self._page = self._browser.new_page()
        
        self._page.on("request", self._handle_request)
        self._page.on("response", self._handle_response)
        self._page.on("download", self._handle_download)

    def _handle_request(self, request):
        self._network.append(TelemetryEvent(
            timestamp=BrowserSandboxAnalyzer._now(),
            event_type="request",
            source=request.frame.url if request.frame else "",
            destination=request.url,
            details={"method": request.method, "resource_type": request.resource_type}
        ))

    def _handle_response(self, response):
        self._network.append(TelemetryEvent(
            timestamp=BrowserSandboxAnalyzer._now(),
            event_type="response",
            source=response.frame.url if response.frame else "",
            destination=response.url,
            details={"status": response.status, "status_text": response.status_text}
        ))

    def _handle_download(self, download):
        self._downloads.append(SandboxDownload(
            url=download.url,
            filename=download.suggested_filename,
            mime=None,
            size=None,
            sha256=None,
            execution_blocked=True,
            content_bytes=None
        ))

    def navigate(self, url: str, timeout_seconds: float) -> None:
        try:
            self._page.goto(url, timeout=timeout_seconds * 1000)
        except Exception as e:
            raise SandboxTimeoutError(str(e)) from e

    def collect_network(self) -> Sequence[TelemetryEvent]:
        return self._network

    def collect_downloads(self) -> Sequence[SandboxDownload]:
        return self._downloads

    def collect_events(self) -> Sequence[TelemetryEvent]:
        return self._events

    def collect_screenshots(self) -> Sequence[ScreenshotArtifact]:
        try:
            image_bytes = self._page.screenshot()
            self._screenshots.append(ScreenshotArtifact.from_bytes(url=self._page.url, image_bytes=image_bytes))
        except Exception:
            pass
        return self._screenshots

    def shutdown(self) -> None:
        if self._browser:
            self._browser.close()
        if self._playwright:
            self._playwright.stop()



class BrowserSandboxAnalyzer:
    def __init__(self, provider: SandboxProvider | None = None, policy: SandboxPolicy | None = None) -> None:
        self.provider = provider or UnavailableSandboxProvider()
        self.policy = policy or SandboxPolicy()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _host(url: str) -> str:
        return (urlsplit(url).hostname or "").lower().rstrip(".")

    def _policy_dict(self) -> dict[str, object]:
        return {
            "timeout_seconds": self.policy.timeout_seconds,
            "max_events": self.policy.max_events,
            "max_download_bytes": self.policy.max_download_bytes,
            "filesystem_access": self.policy.filesystem_access,
            "host_credentials": self.policy.host_credentials,
            "real_browser_profile": self.policy.real_browser_profile,
            "clipboard_access": self.policy.clipboard_access,
            "shared_folders": self.policy.shared_folders,
        }

    def analyze(self, url: str) -> SandboxAnalysis:
        if not is_valid_url(url):
            return SandboxAnalysis("invalid", url, policy=self._policy_dict(), explanation=["URL must be a valid HTTP(S) URL."])
        network: list[TelemetryEvent] = []
        events: list[TelemetryEvent] = []
        screenshots: list[ScreenshotArtifact] = []
        downloads: list[SandboxDownload] = []
        try:
            self.provider.launch(self.policy)
            self.provider.navigate(url, self.policy.timeout_seconds)
            network = list(self.provider.collect_network())[: self.policy.max_events]
            events = list(self.provider.collect_events())[: self.policy.max_events]
            screenshots = list(self.provider.collect_screenshots())[: self.policy.max_events]
            raw_downloads = list(self.provider.collect_downloads())
            for item in raw_downloads[: self.policy.max_events]:
                size = item.size
                if size is not None and size > self.policy.max_download_bytes:
                    downloads.append(SandboxDownload(item.url, item.filename, item.mime, size, item.sha256, True, item.content_bytes))
                else:
                    downloads.append(SandboxDownload(item.url, item.filename, item.mime, size, item.sha256, True, item.content_bytes))
            telemetry = [*network, *events][: self.policy.max_events]
            redirects = [
                {"url": event.destination, "domain": self._host(event.destination or ""), "status_code": event.details.get("status_code"), "source": event.source}
                for event in network
                if event.event_type in {"redirect", "navigation"} and event.destination
            ]
            external_domains = sorted({self._host(event.destination or "") for event in network if event.destination and self._host(event.destination) != self._host(url) and self._host(event.destination)})
            return SandboxAnalysis("completed", url, redirects, telemetry, downloads, external_domains, events, screenshots, self._policy_dict(), ["Observed telemetry came from an isolated provider contract.", "Downloaded files are metadata-only and marked execution_blocked=true."])
        except SandboxTimeoutError:
            return SandboxAnalysis("timeout", url, telemetry=network, downloads=downloads, events=events, screenshots=screenshots, policy=self._policy_dict(), explanation=["Sandbox execution exceeded its timeout limit."])
        except SandboxUnavailableError as error:
            return SandboxAnalysis("unavailable", url, policy=self._policy_dict(), explanation=[str(error), "No browser was launched on the host machine."])
        except Exception:
            return SandboxAnalysis("error", url, telemetry=network, downloads=downloads, events=events, screenshots=screenshots, policy=self._policy_dict(), explanation=["Sandbox provider failed; no behavioral conclusion is drawn."])
        finally:
            try:
                self.provider.shutdown()
            except Exception:
                pass
