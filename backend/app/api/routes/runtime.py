"""Runtime preparation and operational status surfaces."""
from fastapi import APIRouter, Query

from app.core.config import settings
from app.core.preparation_status import read_preparation_status
from app.core.update_check import check_for_update


router = APIRouter(prefix="/runtime", tags=["Runtime"])


@router.get("/preparation")
async def get_preparation_status():
    """Report whether migrations and startup seeds completed successfully."""
    return read_preparation_status()


@router.get("/update")
async def get_update_status(
    force: bool = Query(
        False,
        description="Bypass the cached result for an explicit user-initiated check.",
    ),
):
    """Report whether a newer published release is available.

    Unauthenticated on purpose: the console shows the running version before
    sign-in, and this returns only public release metadata that anyone can read
    from the GitHub releases page.
    """
    return await check_for_update(settings.APP_VERSION, force=force)
