from dataclasses import asdict, replace

from fastapi import APIRouter, Depends, HTTPException, status

from ..database.database import save_scan
from ..schemas.phishing import AIExplainRequest, HTMLAnalysisResponse, JavaScriptAnalysisResponse, PhishingScanRequest, PhishingScanResponse, PhishingUrlAnalysisResponse
from ..services.llm_explainer import explain_with_gemini
from ..schemas.sandbox import SandboxAnalysisResponse
from ..schemas.visual import VisualAnalysisResponse
from ..schemas.website_download import WebsiteDownloadReportResponse
from ..services.phishing_detector import ModelUnavailableError, PhishingDetector
from ..services.url_analyzer import URLAnalyzer
from ..services.html_analyzer import HTMLAnalyzer, HTMLFetchError
from ..services.javascript_analyzer import JavaScriptAnalyzer
from ..services.phishing_pipeline import PhishingPipeline
from ..services.browser_sandbox import BrowserSandboxAnalyzer
from ..services.visual_analyzer import VisualAnalyzer
from ..services.website_download_analyzer import WebsiteDownloadAnalyzer

# ==============================================================================
# PHISHING SCANNER API ROUTER
# Điểm tiếp nhận request phân tích URL từ Frontend Dashboard (/api/phishing/analyze)
# ==============================================================================

router = APIRouter(prefix="/api/phishing", tags=["phishing"])
_detector = PhishingDetector()
_url_analyzer = URLAnalyzer()
_html_analyzer = HTMLAnalyzer()
_javascript_analyzer = JavaScriptAnalyzer()
_phishing_pipeline = PhishingPipeline(_html_analyzer, _javascript_analyzer)
try:
    from ..services.browser_sandbox import PlaywrightSandboxProvider
    _sandbox_analyzer = BrowserSandboxAnalyzer(provider=PlaywrightSandboxProvider())
except (ImportError, Exception):
    _sandbox_analyzer = BrowserSandboxAnalyzer()

try:
    from ..services.visual_analyzer import BasicVisionProvider
    _visual_analyzer = VisualAnalyzer(provider=BasicVisionProvider())
except (ImportError, Exception):
    _visual_analyzer = VisualAnalyzer()

try:
    from ..services.website_download_analyzer import ExistingMalwareScannerAdapter
    _download_analyzer = WebsiteDownloadAnalyzer(malware_scanner=ExistingMalwareScannerAdapter())
except (ImportError, Exception):
    _download_analyzer = WebsiteDownloadAnalyzer()


def get_phishing_detector() -> PhishingDetector:
    """Dependency injection cung cấp singleton instance của PhishingDetector."""
    return _detector


def get_html_analyzer() -> HTMLAnalyzer:
    return _html_analyzer


def get_phishing_pipeline() -> PhishingPipeline:
    return _phishing_pipeline


def get_sandbox_analyzer() -> BrowserSandboxAnalyzer:
    return _sandbox_analyzer


def get_visual_analyzer() -> VisualAnalyzer:
    return _visual_analyzer


def get_download_analyzer() -> WebsiteDownloadAnalyzer:
    return _download_analyzer


@router.post("/url-analysis", response_model=PhishingUrlAnalysisResponse)
def analyze_url_structure(request: PhishingScanRequest) -> PhishingUrlAnalysisResponse:
    """Return Phase 1 structured URL/domain evidence without loading the ML model."""
    try:
        url = str(request.url)
        url_result = _url_analyzer.analyze(url)
        domain_result = _url_analyzer.domain_analyzer.analyze(url)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(error)) from error
    return PhishingUrlAnalysisResponse(
        url=url,
        url_analysis=asdict(url_result),
        domain_analysis=asdict(domain_result),
    )


@router.post("/html-analysis", response_model=HTMLAnalysisResponse)
def analyze_html_structure(
    request: PhishingScanRequest,
    analyzer: HTMLAnalyzer = Depends(get_html_analyzer),
) -> HTMLAnalysisResponse:
    """Fetch and parse HTML without executing scripts or submitting forms."""
    try:
        result = analyzer.analyze_url(str(request.url))
    except HTMLFetchError as error:
        raise HTTPException(status_code=error.status_code, detail=str(error)) from error
    return HTMLAnalysisResponse(
        url=str(request.url),
        final_url=result.final_url,
        html_score=result.html_score,
        forms=result.forms,
        credential_fields=result.credential_fields,
        external_submissions=result.external_submissions,
        iframes=result.iframes,
        external_resources=result.external_resources,
        external_scripts=result.external_scripts,
        indicators=result.indicators,
        explanation=result.explanation,
        status=result.status,
        http_status=result.http_status,
        content_type=result.content_type,
    )


@router.post("/javascript-analysis", response_model=JavaScriptAnalysisResponse)
def analyze_javascript_structure(
    request: PhishingScanRequest,
    analyzer: HTMLAnalyzer = Depends(get_html_analyzer),
) -> JavaScriptAnalysisResponse:
    """Fetch HTML and inspect JavaScript source statically without executing it."""
    try:
        html_result = analyzer.analyze_url(str(request.url))
        js_result = _javascript_analyzer.analyze(
            inline_scripts=html_result.inline_scripts,
            external_scripts=html_result.external_scripts,
            page_url=html_result.final_url,
        )
    except HTMLFetchError as error:
        raise HTTPException(status_code=error.status_code, detail=str(error)) from error
    return JavaScriptAnalysisResponse(
        url=str(request.url),
        final_url=html_result.final_url,
        **asdict(js_result),
    )


@router.post("/sandbox-analysis", response_model=SandboxAnalysisResponse)
def analyze_browser_behavior(
    request: PhishingScanRequest,
    analyzer: BrowserSandboxAnalyzer = Depends(get_sandbox_analyzer),
) -> SandboxAnalysisResponse:
    """Run only through an explicitly configured isolated sandbox provider."""
    result = analyzer.analyze(str(request.url))
    return SandboxAnalysisResponse(**asdict(result))


@router.post("/visual-analysis", response_model=VisualAnalysisResponse)
def analyze_visual_phishing(
    request: PhishingScanRequest,
    sandbox: BrowserSandboxAnalyzer = Depends(get_sandbox_analyzer),
    visual: VisualAnalyzer = Depends(get_visual_analyzer),
) -> VisualAnalysisResponse:
    """Analyze a screenshot supplied by the isolated sandbox provider."""
    url = str(request.url)
    sandbox_result = sandbox.analyze(url)
    screenshot = sandbox_result.screenshots[-1] if sandbox_result.screenshots else None
    domain_context = asdict(_url_analyzer.domain_analyzer.analyze(url))
    html_context: dict[str, object] = {}
    if screenshot is not None:
        try:
            html_context = asdict(_html_analyzer.analyze_url(url))
        except Exception:
            html_context = {}
    threat_context = []
    if screenshot is not None:
        try:
            threat_context = [asdict(item) for item in _phishing_pipeline.threat_intel.lookup("URL", url)]
        except Exception:
            threat_context = []
    result = visual.analyze(screenshot, page_url=url, domain_analysis=domain_context, html_analysis=html_context, threat_intelligence=threat_context)
    return VisualAnalysisResponse(**asdict(result))


@router.post("/download-analysis", response_model=WebsiteDownloadReportResponse)
def analyze_website_downloads(
    request: PhishingScanRequest,
    sandbox: BrowserSandboxAnalyzer = Depends(get_sandbox_analyzer),
    downloads: WebsiteDownloadAnalyzer = Depends(get_download_analyzer),
) -> WebsiteDownloadReportResponse:
    """Analyze only files actually observed by the isolated sandbox."""
    url = str(request.url)
    sandbox_result = sandbox.analyze(url)
    website_risk = _url_analyzer.analyze(url).severity
    report = downloads.analyze(sandbox_result, website_risk=website_risk)
    return WebsiteDownloadReportResponse(**asdict(report))


@router.post("/analyze", response_model=PhishingScanResponse)
def analyze_phishing_url(
    request: PhishingScanRequest,
    detector: PhishingDetector = Depends(get_phishing_detector),
    pipeline: PhishingPipeline = Depends(get_phishing_pipeline),
) -> PhishingScanResponse:
    """Xử lý yêu cầu quét URL lừa đảo từ giao diện web:
    1. Tiếp nhận và kiểm tra schema URL hợp lệ
    2. Chuyển cho PhishingDetector thực hiện trích xuất và suy luận ML
    3. Lưu lại kết quả vào bảng lịch sử quét (SQLite database)
    4. Trả về kết quả phân tích JSON chi tiết kèm điểm rủi ro & giải thích SHAP
    """
    url = str(request.url)
    try:
        # Gọi tầng service lõi để phân tích URL
        analysis = detector.analyze(url)
    except ModelUnavailableError as error:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(error)) from error

    phase5 = pipeline.analyze(
        url,
        url_analysis=analysis.url_analysis,
        domain_analysis=analysis.domain_analysis,
        model_probability=analysis.probability,
    )
    analysis = replace(
        analysis,
        html_analysis=phase5.html_analysis,
        javascript_analysis=phase5.javascript_analysis,
        threat_intelligence=phase5.threat_intelligence,
        risk_report=phase5.risk_report,
    )
    response_payload = asdict(analysis)
    response_payload["html_analysis"]["url"] = url
    response_payload["javascript_analysis"]["url"] = url
    response_payload["javascript_analysis"]["final_url"] = response_payload["html_analysis"].get("final_url", url)

    try:
        response_payload["ai_explanation"] = explain_with_gemini(response_payload)
    except Exception:
        response_payload["ai_explanation"] = None

    response = PhishingScanResponse(**response_payload)

    # Lưu bản ghi quét vào cơ sở dữ liệu SQLite cục bộ
    save_scan(
        scan_type="PHISHING",
        target=response.url,
        sha256=None,
        prediction=response.prediction,
        probability=response.probability,
        risk_score=response.risk_score,
        risk_level=response.risk_level,
    )
    return response


@router.post("/ai-explain")
def generate_friendly_explanation(request: AIExplainRequest) -> dict[str, object]:
    """Generate or re-generate plain-language advice for non-tech users via Gemini API."""
    return explain_with_gemini(request.scan_data, api_key=request.api_key)
