"""Execution Coordinator: drives a durable Cowork job to a terminal state.

Division of responsibility, per the Cowork contract:

* the **Brain** (local model, API, subscription CLI, or Browser Companion) plans
  and authors -- it is an advisor and never touches the filesystem;
* the **Coordinator** (this module) inspects the workspace, invokes the Brain,
  and then hands any resulting changes to the existing deterministic governed
  writer in ``workspace.py``.

That writer is deliberately reused rather than reimplemented: it already carries
the Trust Fabric decision, path containment, Office rendering, artifact
versioning, and native mirroring. Nothing here bypasses it, and no model is ever
given write authority.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.marcellus import cowork_jobs as jobs
from app.core.marcellus import cowork_states as states
from app.core.marcellus.cowork_commands import (
    NO_EXECUTOR_REASON,
    CommandOutcome,
    VerificationReport,
    authorize_command,
    detect_commands,
    failure_capsule,
    run_command,
)
from app.core.marcellus.cowork_executors import (
    DENIED,
    EXECUTOR_LABELS,
    FAILED,
    NOT_RUN,
    PASSED,
    resolve_executor,
)
from app.core.marcellus.cowork_inspection import inspect_project
from app.core.marcellus.crypto import decrypt_json, encrypt_json
from app.core.marcellus.native_workspace import get_binding
from app.core.marcellus.workspace_schemas import CortexTurnCreate
from app.models.marcellus import CoworkJob

logger = logging.getLogger("marcellus.cowork.runner")

#: Sources whose answers arrive through the Browser Companion. These are the
#: only sources that get the durable browser-task treatment.
BROWSER_SOURCES = {"chatgpt_browser", "claude_browser", "gemini_browser"}

#: How many times a failing verification may be re-run before the job stops
#: trying. Bounded so a genuinely broken build fails fast instead of looping.
MAX_VERIFY_ATTEMPTS = 2


def _job_request(job: CoworkJob) -> dict[str, Any]:
    try:
        value = decrypt_json(job.request_ciphertext, job.request_digest)
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


async def _store_result(db: AsyncSession, job: CoworkJob, result: dict[str, Any]) -> None:
    ciphertext, digest = encrypt_json(result)
    job.result_ciphertext = ciphertext
    job.result_digest = digest


def job_result(job: CoworkJob) -> dict[str, Any] | None:
    if not job.result_ciphertext:
        return None
    try:
        value = decrypt_json(job.result_ciphertext, job.result_digest)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


async def run_job(db: AsyncSession, job: CoworkJob) -> None:
    """Advance one claimed job to a terminal state on its own session."""
    from app.core.marcellus.workspace import execute_turn, _get_conversation

    request = _job_request(job)
    payload_data = request.get("turn") or {}
    inspect_requested = bool(request.get("inspect_workspace", True))
    user = request.get("user") or {}
    actor = str(request.get("actor_id") or job.owner_id)

    conversation = await _get_conversation(db, job.tenant_id, job.conversation_id)

    # --- planning ------------------------------------------------------
    plan_step = await jobs.add_step(db, job, kind="plan", label="Plan the requested work")
    await jobs.start_step(db, job, plan_step, states.PLANNING)
    await jobs.finish_step(db, job, plan_step, ok=True)
    await db.commit()

    if job.cancel_requested:
        return

    # --- workspace inspection -------------------------------------------
    inspection_brief = ""
    inspection = None
    if inspect_requested and job.project_id:
        inspect_step = await jobs.add_step(
            db, job, kind="inspect_workspace", label="Inspect the approved project"
        )
        await jobs.start_step(db, job, inspect_step, states.INSPECTING_WORKSPACE)
        inspection = await inspect_project(
            db,
            tenant_id=job.tenant_id,
            project_id=job.project_id,
            prompt=str(payload_data.get("content") or ""),
            branch=job.workspace_branch,
        )
        job.workspace_snapshot_digest = inspection.snapshot_digest or None
        inspection_brief = inspection.as_brief()
        await jobs.append_event(
            db,
            job,
            event_type="workspace_inspected",
            step_id=inspect_step.id,
            payload=inspection.summary(),
        )
        await jobs.finish_step(db, job, inspect_step, ok=True)
        await db.commit()

    if job.cancel_requested:
        return

    # --- brain ----------------------------------------------------------
    source = str(payload_data.get("source") or job.source or "")
    is_browser = source in BROWSER_SOURCES
    brain_step = await jobs.add_step(
        db, job, kind="brain", label=f"Consult {source or 'the selected Brain'}"
    )
    await jobs.start_step(db, job, brain_step, states.CONTEXT_COMPILING)
    await jobs.transition(db, job, states.WAITING_FOR_BRAIN, step_id=brain_step.id)
    if is_browser:
        await jobs.append_event(
            db,
            job,
            event_type="browser_state",
            step_id=brain_step.id,
            payload={"provider": source, "state": "waiting"},
        )
    await db.commit()

    turn_payload = dict(payload_data)
    if inspection_brief:
        # The inspection is prepended as clearly-labelled untrusted context, so
        # the Brain plans against the real project instead of guessing.
        turn_payload["content"] = f"{inspection_brief}\n\n---\n\n{turn_payload.get('content', '')}"
    turn_payload["tenant_id"] = job.tenant_id

    # Both callbacks are synchronous and are invoked from inside the turn, so
    # they buffer rather than write: appending an event requires the async
    # session, and touching it mid-turn would interleave with the turn's own
    # transaction. The buffers are drained below, once the turn has returned.
    progress_events: list[tuple[str, str, str | None]] = []

    def on_progress(progress_source: str, state: str, label: str | None) -> None:
        progress_events.append((progress_source, state, label))

    file_events: list[tuple[str, str, str]] = []

    def on_file_progress(path: str, operation: str, outcome: str) -> None:
        file_events.append((path, operation, outcome))

    try:
        turn = await execute_turn(
            db,
            job.tenant_id,
            job.conversation_id,
            CortexTurnCreate.model_validate(turn_payload),
            user=user,
            actor_id=actor,
            on_progress=on_progress,
            on_file_progress=on_file_progress,
        )
    except HTTPException as exc:
        await db.rollback()
        fresh = await db.get(CoworkJob, job.id)
        if fresh is not None and not states.is_terminal(fresh.state):
            # HTTPException detail here is server-authored (never provider text),
            # so it is safe to surface to the owning operator.
            await jobs.transition(db, fresh, states.FAILED, detail=str(exc.detail)[:500])
            await db.commit()
        return

    if job.state == states.WAITING_FOR_BRAIN:
        await jobs.transition(db, job, states.BRAIN_STREAMING, step_id=brain_step.id)
    for progress_source, progress_state, progress_label in progress_events:
        await jobs.append_event(
            db,
            job,
            event_type="brain_progress",
            step_id=brain_step.id,
            payload={
                "source": progress_source,
                "state": progress_state,
                "label": progress_label,
            },
        )
    await jobs.finish_step(db, job, brain_step, ok=True)

    governance = (turn.assistant_message.governance if turn.assistant_message else {}) or {}

    # --- deterministic file effects --------------------------------------
    applied = list(governance.get("applied_change_paths") or [])
    proposals = list(governance.get("change_proposal_ids") or [])
    if applied or file_events:
        write_step = await jobs.add_step(
            db, job, kind="write_files", label="Apply governed file changes"
        )
        await jobs.start_step(db, job, write_step, states.WRITING_FILES)
        for path, operation, outcome in file_events:
            await jobs.append_event(
                db,
                job,
                event_type="file_progress",
                step_id=write_step.id,
                payload={"path": path, "operation": operation, "outcome": outcome},
            )
        await jobs.finish_step(
            db, job, write_step, ok=True, payload={"applied": len(applied)}
        )
    elif proposals:
        approval_step = await jobs.add_step(
            db, job, kind="await_approval", label="Await change approval", retryable=False
        )
        await jobs.start_step(db, job, approval_step, states.AWAITING_APPROVAL)
        await jobs.append_event(
            db,
            job,
            event_type="changes_proposed",
            step_id=approval_step.id,
            payload={"proposal_ids": [str(item) for item in proposals], "count": len(proposals)},
        )
        result = {
            "conversation_id": str(job.conversation_id),
            "proposal_ids": [str(item) for item in proposals],
            "applied_paths": [],
            "awaiting_approval": True,
        }
        await _store_result(db, job, result)
        await db.commit()
        # A job waiting on a human is not finished and must not be timed out on
        # the provider clock; it stays durable until the operator decides.
        return

    # --- governed command execution + verification ------------------------
    report = VerificationReport()
    if applied and inspection is not None:
        report = await _verify_after_write(
            db,
            job,
            inspection=inspection,
            actor=actor,
            user=user,
            approved_paths=applied,
        )
    else:
        verify_step = await jobs.add_step(db, job, kind="verify", label="Verify the result")
        await jobs.start_step(db, job, verify_step, states.VERIFYING)
        await jobs.finish_step(db, job, verify_step, ok=True, payload={"applied": len(applied)})

    await _store_result(
        db,
        job,
        {
            "conversation_id": str(job.conversation_id),
            "applied_paths": applied,
            "proposal_ids": [str(item) for item in proposals],
            "awaiting_approval": False,
            "verification": report.as_payload(),
            "assistant_message_id": str(turn.assistant_message.id) if turn.assistant_message else None,
        },
    )
    # "completed" alone never implies verification: the outcome records whether a
    # real command actually passed, failed, or never ran.
    job.outcome = states.completion_outcome(
        verified=report.verified, had_failures=bool(report.failed)
    )
    await jobs.append_event(
        db,
        job,
        event_type="job_outcome",
        payload={
            "outcome": job.outcome,
            "verified": report.verified,
            "executor": report.executor,
            "executor_label": report.executor_label,
        },
    )
    await jobs.transition(db, job, states.COMPLETED)
    await db.commit()


async def _verify_after_write(
    db: AsyncSession,
    job: CoworkJob,
    *,
    inspection,
    actor: str,
    user: dict[str, Any],
    approved_paths: list[str],
) -> VerificationReport:
    """Detect, authorize, and run checks through the selected Executor.

    On failure the loop hands the Brain a bounded failure capsule, applies only
    changes scoped to files this job already touched, and re-runs the failing
    command within a retry budget. The Brain never executes anything itself and
    the deterministic writer remains the only thing that touches files.
    """
    report = VerificationReport()
    plans = detect_commands(inspection)

    binding = get_binding(job.tenant_id, job.project_id) if job.project_id else None
    token = (binding or {}).get("token")
    scope_digest = job.workspace_snapshot_digest or ""

    executor, availability = await resolve_executor(job.executor_preference or "auto", token=token)
    report.executor = availability.executor
    report.executor_label = EXECUTOR_LABELS.get(availability.executor, availability.executor)
    job.executor_used = availability.executor if executor is not None else None
    await jobs.append_event(
        db,
        job,
        event_type="executor_selected",
        payload={
            "requested": job.executor_preference,
            **availability.as_payload(),
        },
    )

    if not plans:
        verify_step = await jobs.add_step(db, job, kind="verify", label="Verify the result")
        await jobs.start_step(db, job, verify_step, states.VERIFYING)
        await jobs.append_event(
            db,
            job,
            event_type="verification_skipped",
            step_id=verify_step.id,
            payload={"reason": "No test, build, or lint command was detected for this project."},
        )
        await jobs.finish_step(db, job, verify_step, ok=True)
        await db.commit()
        return report

    if executor is None:
        # Every executor is unavailable. Record it plainly; nothing is promoted
        # to a pass, and the message names no specific product.
        report.execution_unavailable = True
        report.unavailable_reason = NO_EXECUTOR_REASON
        report.outcomes = [
            CommandOutcome(
                plan.kind, plan.command, NOT_RUN, detail=NO_EXECUTOR_REASON, executor="unavailable"
            )
            for plan in plans
        ]
        verify_step = await jobs.add_step(db, job, kind="verify", label="Summarize verification")
        await jobs.start_step(db, job, verify_step, states.VERIFYING)
        await jobs.append_event(
            db,
            job,
            event_type="execution_unavailable",
            step_id=verify_step.id,
            payload={
                "reason": NO_EXECUTOR_REASON,
                "detected_commands": [plan.command for plan in plans],
                "executor": "unavailable",
            },
        )
        await jobs.finish_step(db, job, verify_step, ok=True)
        await db.commit()
        return report

    for plan in plans:
        step = await jobs.add_step(db, job, kind=f"command:{plan.kind}", label=f"Run {plan.command}")
        running_state = states.RUNNING_TESTS if plan.kind == "test" else states.RUNNING_COMMAND
        await jobs.start_step(db, job, step, running_state)
        allowed = await authorize_command(
            db,
            tenant_id=job.tenant_id,
            actor_id=actor,
            actor_name=str(user.get("email") or actor),
            conversation_id=job.conversation_id,
            project_id=job.project_id,
            classification=job.classification,
            kind=plan.kind,
        )
        if not allowed:
            outcome = CommandOutcome(
                plan.kind, plan.command, DENIED, detail="Denied by policy", executor=executor.name
            )
            report.outcomes.append(outcome)
            await jobs.append_event(
                db, job, event_type="command_result", step_id=step.id, payload=outcome.as_payload()
            )
            await jobs.finish_step(db, job, step, ok=False, detail="Denied by policy")
            await db.commit()
            continue

        outcome = await run_command(
            plan=plan, executor=executor, token=token, scope_digest=scope_digest, db=db, job=job
        )
        attempts = 1
        while outcome.status == FAILED and attempts < MAX_VERIFY_ATTEMPTS:
            if job.cancel_requested:
                await executor.cancel(
                    execution_id=outcome.execution_id, token=token, scope_digest=scope_digest
                )
                break
            await jobs.transition(db, job, states.DEBUGGING, step_id=step.id)
            capsule = failure_capsule([outcome], approved_paths=approved_paths)
            await jobs.append_event(
                db,
                job,
                event_type="failure_capsule",
                step_id=step.id,
                payload={"capsule": capsule, "approved_paths": approved_paths[:20]},
            )
            fixed = await _request_brain_fix(
                db,
                job,
                capsule=capsule,
                approved_paths=approved_paths,
                user=user,
                actor=actor,
                step_id=step.id,
            )
            await jobs.append_event(
                db,
                job,
                event_type="command_retry",
                step_id=step.id,
                payload={
                    "kind": plan.kind,
                    "attempt": attempts,
                    "exit_code": outcome.exit_code,
                    "brain_applied_paths": fixed,
                },
            )
            await db.commit()
            await jobs.transition(db, job, running_state, step_id=step.id)
            outcome = await run_command(
                plan=plan, executor=executor, token=token, scope_digest=scope_digest, db=db, job=job
            )
            attempts += 1

        outcome.attempts = attempts
        report.outcomes.append(outcome)
        await jobs.append_event(
            db, job, event_type="command_result", step_id=step.id, payload=outcome.as_payload()
        )
        await jobs.finish_step(
            db, job, step, ok=outcome.status == PASSED, detail=outcome.detail or None
        )
        await db.commit()

    verify_step = await jobs.add_step(db, job, kind="verify", label="Summarize verification")
    await jobs.start_step(db, job, verify_step, states.VERIFYING)
    await jobs.append_event(
        db, job, event_type="verification_complete", step_id=verify_step.id, payload=report.as_payload()
    )
    await jobs.finish_step(db, job, verify_step, ok=not report.failed)
    await db.commit()
    return report


async def _request_brain_fix(
    db: AsyncSession,
    job: CoworkJob,
    *,
    capsule: str,
    approved_paths: list[str],
    user: dict[str, Any],
    actor: str,
    step_id,
) -> list[str]:
    """Ask the selected Brain to fix a failing check, scoped to approved files.

    Any Brain works here -- browser, Ollama, API, or subscription -- because the
    fix arrives as ordinary change protocol output and is applied by the same
    deterministic writer. Changes touching files outside ``approved_paths`` are
    dropped rather than written.
    """
    from app.core.marcellus.workspace import execute_turn

    request = _job_request(job)
    payload_data = dict(request.get("turn") or {})
    payload_data["tenant_id"] = job.tenant_id
    payload_data["content"] = (
        f"{capsule}\n\nFix the failure above. Change only the listed files and "
        "return the corrected file contents using the governed change protocol."
    )
    payload_data["agent_mode"] = True
    payload_data["include_project_files"] = False
    try:
        turn = await execute_turn(
            db,
            job.tenant_id,
            job.conversation_id,
            CortexTurnCreate.model_validate(payload_data),
            user=user,
            actor_id=actor,
        )
    except HTTPException as exc:
        await jobs.append_event(
            db,
            job,
            event_type="brain_fix_failed",
            step_id=step_id,
            payload={"detail": str(exc.detail)[:300]},
        )
        return []
    governance = (turn.assistant_message.governance if turn.assistant_message else {}) or {}
    applied = [
        path for path in (governance.get("applied_change_paths") or []) if path in set(approved_paths)
    ]
    return applied
