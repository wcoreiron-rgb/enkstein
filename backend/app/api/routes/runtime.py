"""Runtime preparation and operational status surfaces."""
from fastapi import APIRouter

from app.core.preparation_status import read_preparation_status


router = APIRouter(prefix="/runtime", tags=["Runtime"])


@router.get("/preparation")
async def get_preparation_status():
    """Report whether migrations and startup seeds completed successfully."""
    return read_preparation_status()
