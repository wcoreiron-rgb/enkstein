"""
Enkstein — Copilot API Routes
Natural-language workflow creation: NL → draft → policy eval → approve → run.
"""
import logging
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.services.nl_workflow_generator import (
    generate_workflow_draft,
    get_draft,
    list_drafts,
    discard_draft,
    patch_draft_workflow,
)

logger = logging.getLogger("regentclaw.copilot")
router = APIRouter(prefix="/copilot", tags=["Copilot"])


# ─── Request / Response schemas ──────────────────────────────────────────────

class NLRequest(BaseModel):
    prompt: str = Field(..., min_length=5, max_length=2000,
                        description="Natural-language security intent.")
    requested_by: str = Field(default="copilot_ui",
                              description="Identifier of the requesting user/session.")


class PatchDraftRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    trigger_type: str | None = None
    category: str | None = None
    tags: str | None = None


class ApproveRequest(BaseModel):
    approved_by: str = Field(default="copilot_ui")
    run_immediately: bool = Field(
        default=False,
        description="If True, fire the workflow right after saving; otherwise just save as DRAFT.",
    )


# ─── Endpoints ───────────────────────────────────────────────────────────────

@router.post("/nl-to-workflow", summary="Parse NL prompt → workflow draft")
async def nl_to_workflow(body: NLRequest):
    """
    Accepts a plain-English security intent and returns a structured
    workflow draft with an inline policy evaluation.

    The draft is stored in memory (keyed by draft_id) awaiting approval.
    """
    draft = generate_workflow_draft(
        prompt=body.prompt,
        requested_by=body.requested_by,
    )
    logger.info(
        "NL draft generated: draft_id=%s status=%s risk=%s",
        draft["draft_id"],
        draft["status"],
        draft["policy_evaluation"]["risk_level"],
    )
    return draft


@router.get("/drafts", summary="List all pending drafts")
async def get_drafts():
    drafts = list_drafts()
    return {"count": len(drafts), "drafts": drafts}


@router.get("/drafts/{draft_id}", summary="Get a specific draft")
async def get_one_draft(draft_id: str):
    draft = get_draft(draft_id)
    if not draft:
        raise HTTPException(status_code=404, detail="Draft not found")
    return draft


@router.patch("/drafts/{draft_id}", summary="Update draft workflow metadata")
async def patch_draft(draft_id: str, body: PatchDraftRequest):
    updates = {k: v for k, v in body.dict().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    draft = patch_draft_workflow(draft_id, updates)
    if draft is None:
        raise HTTPException(status_code=404, detail="Draft not found")
    return draft


@router.delete("/drafts/{draft_id}", summary="Discard a draft")
async def delete_draft(draft_id: str):
    if not discard_draft(draft_id):
        raise HTTPException(status_code=404, detail="Draft not found")
    return {"deleted": draft_id}


@router.post("/drafts/{draft_id}/approve", summary="Approve draft → save (+ optional run)")
async def approve_draft(
    draft_id: str,
    body: ApproveRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Approve a draft:
    1. Create the Workflow record in the DB (status = DRAFT or ACTIVE).
    2. Optionally fire an immediate WorkflowRun.
    3. Discard the in-memory draft.
    """
    from sqlalchemy import select
    from app.models.workflow import Workflow, WorkflowRun, WorkflowStatus

    draft = get_draft(draft_id)
    if not draft:
        raise HTTPException(status_code=404, detail="Draft not found")

    wf_payload = draft["workflow"]

    # ── Create Workflow ──────────────────────────────────────────────────────
    new_status = (
        WorkflowStatus.ACTIVE if body.run_immediately else WorkflowStatus.DRAFT
    )
    wf = Workflow(
        name=wf_payload["name"],
        description=wf_payload.get("description"),
        trigger_type=wf_payload.get("trigger_type", "manual"),
        status=new_status,
        is_active=body.run_immediately,
        steps_json=wf_payload["steps_json"],
        step_count=wf_payload.get("step_count", 0),
        category=wf_payload.get("category", "AI-Generated"),
        tags=wf_payload.get("tags", ""),
        created_by=body.approved_by,
    )
    db.add(wf)
    await db.flush()  # get wf.id

    run_id = None
    run_status = None

    # ── Optionally launch the workflow ───────────────────────────────────────
    if body.run_immediately:
        from app.services.workflow_runner import run_workflow
        run = await run_workflow(db, str(wf.id), triggered_by=body.approved_by)
        run_id    = str(run.id)
        run_status = run.status.value

    await db.commit()

    # Clean up draft
    discard_draft(draft_id)

    logger.info(
        "Draft approved: workflow_id=%s run_immediately=%s",
        str(wf.id), body.run_immediately,
    )

    return {
        "workflow_id": str(wf.id),
        "workflow_name": wf.name,
        "workflow_status": new_status.value,
        "run_id": run_id,
        "run_status": run_status,
        "message": (
            f"Workflow created and run started (run_id={run_id})"
            if body.run_immediately
            else "Workflow saved as draft. Launch it from Orchestrations."
        ),
    }


@router.post("/drafts/{draft_id}/save-template", summary="Save draft as reusable template")
async def save_as_template(
    draft_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Save the draft as a DRAFT workflow without running it."""
    from app.models.workflow import Workflow, WorkflowStatus

    draft = get_draft(draft_id)
    if not draft:
        raise HTTPException(status_code=404, detail="Draft not found")

    wf_payload = draft["workflow"]
    wf = Workflow(
        name=wf_payload["name"],
        description=wf_payload.get("description"),
        trigger_type=wf_payload.get("trigger_type", "manual"),
        status=WorkflowStatus.DRAFT,
        is_active=False,
        steps_json=wf_payload["steps_json"],
        step_count=wf_payload.get("step_count", 0),
        category=wf_payload.get("category", "AI-Generated"),
        tags=wf_payload.get("tags", ""),
        created_by=draft.get("requested_by", "copilot"),
    )
    db.add(wf)
    await db.commit()
    discard_draft(draft_id)

    return {
        "workflow_id": str(wf.id),
        "workflow_name": wf.name,
        "message": "Saved as draft template. Open Orchestrations to activate.",
    }
