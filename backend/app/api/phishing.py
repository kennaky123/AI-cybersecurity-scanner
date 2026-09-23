from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException, status

from ..database.database import save_scan
from ..schemas.phishing import PhishingScanRequest, PhishingScanResponse
from ..services.phishing_detector import ModelUnavailableError, PhishingDetector

# ==============================================================================
# PHISHING SCANNER API ROUTER
# Điểm tiếp nhận request phân tích URL từ Frontend Dashboard (/api/phishing/analyze)
# ==============================================================================

router = APIRouter(prefix="/api/phishing", tags=["phishing"])
_detector = PhishingDetector()


def get_phishing_detector() -> PhishingDetector:
    """Dependency injection cung cấp singleton instance của PhishingDetector."""
    return _detector


@router.post("/analyze", response_model=PhishingScanResponse)
def analyze_phishing_url(
    request: PhishingScanRequest,
    detector: PhishingDetector = Depends(get_phishing_detector),
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

    response = PhishingScanResponse(**asdict(analysis))

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
