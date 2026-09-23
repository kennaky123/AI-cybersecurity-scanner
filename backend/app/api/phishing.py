from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException, status

from ..database.database import save_scan
from ..schemas.phishing import PhishingScanRequest, PhishingScanResponse
from ..services.phishing_detector import ModelUnavailableError, PhishingDetector

router = APIRouter(prefix="/api/phishing", tags=["phishing"])
_detector = PhishingDetector()


def get_phishing_detector() -> PhishingDetector:
    return _detector


@router.post("/analyze", response_model=PhishingScanResponse)
def analyze_phishing_url(
    request: PhishingScanRequest,
    detector: PhishingDetector = Depends(get_phishing_detector),
) -> PhishingScanResponse:
    url = str(request.url)
    try:
        analysis = detector.analyze(url)
    except ModelUnavailableError as error:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(error)) from error

    response = PhishingScanResponse(**asdict(analysis))
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
