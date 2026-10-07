from dataclasses import asdict

from fastapi import APIRouter, Depends

from ..schemas.threat_intelligence import ThreatIntelLookupRequest, ThreatIntelLookupResponse
from ..services.threat_intelligence import ThreatIntelManager

router = APIRouter(prefix="/api/threat-intelligence", tags=["threat-intelligence"])
_manager = ThreatIntelManager()


def get_threat_intel_manager() -> ThreatIntelManager:
    return _manager


@router.post("/lookup", response_model=ThreatIntelLookupResponse)
def lookup_threat_intelligence(
    request: ThreatIntelLookupRequest,
    manager: ThreatIntelManager = Depends(get_threat_intel_manager),
) -> ThreatIntelLookupResponse:
    results = manager.lookup(request.indicator_type, request.value)
    return ThreatIntelLookupResponse(
        indicator_type=request.indicator_type,
        value=request.value,
        results=[asdict(result) for result in results],
    )
