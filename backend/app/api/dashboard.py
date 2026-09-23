from fastapi import APIRouter

from ..database.database import fetch_dashboard_data

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("")
def dashboard() -> dict[str, object]:
    return fetch_dashboard_data()
