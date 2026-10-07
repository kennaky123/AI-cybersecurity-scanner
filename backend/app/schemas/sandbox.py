from pydantic import BaseModel


class TelemetryEventResponse(BaseModel):
    timestamp: str
    event_type: str
    source: str
    destination: str | None
    details: dict[str, object]


class SandboxDownloadResponse(BaseModel):
    url: str
    filename: str | None
    mime: str | None
    size: int | None
    sha256: str | None
    execution_blocked: bool


class ScreenshotArtifactResponse(BaseModel):
    url: str
    mime: str
    width: int | None
    height: int | None
    sha256: str


class SandboxAnalysisResponse(BaseModel):
    status: str
    url: str
    redirect_chain: list[dict[str, object]]
    telemetry: list[TelemetryEventResponse]
    downloads: list[SandboxDownloadResponse]
    external_domains: list[str]
    events: list[TelemetryEventResponse]
    screenshots: list[ScreenshotArtifactResponse]
    policy: dict[str, object]
    explanation: list[str]
