from typing import Literal

from fastapi import APIRouter, Query

from ..database.database import fetch_scan_history

router = APIRouter(prefix="/api/history", tags=["history"])


@router.get("")
def list_scan_history(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    scan_type: Literal["PHISHING", "MALWARE"] | None = None,
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None,
    search: str | None = Query(default=None, max_length=200),
    sort_order: Literal["asc", "desc"] = "desc",
) -> dict[str, object]:
    return fetch_scan_history(
        page=page,
        page_size=page_size,
        scan_type=scan_type,
        risk_level=risk_level,
        search=search,
        sort_order=sort_order,
    )
