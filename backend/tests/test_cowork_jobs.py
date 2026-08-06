"""Durable Cowork job, executor, and security tests.

These exercise the real state machine, the real durable store, and the real
executor selection logic. Native command execution itself is stubbed at the
bridge boundary (there is no desktop broker in CI), but the containment,
allowlist, and argv rules are tested directly against the parser that the
broker mirrors.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
from sqlalchemy import select

from app.core.deps import get_current_user
from app.core.marcellus import cowork_executors as executors
from app.core.marcellus import cowork_jobs as jobs
from app.core.marcellus import cowork_states as states
from app.core.marcellus import workspace
from app.core.marcellus.cowork_commands import (
    CommandPlan,
    VerificationReport,
    detect_commands,
    failure_capsule,
    is_command_safe,
    redact_output,
    run_command,
)
from app.core.marcellus.cowork_inspection import inspect_project
from app.models.marcellus import CoworkExecution, CoworkJob, CoworkJobEvent
from main import app


BASE = "/api/v1/marcellus/workspace"
COWORK = "/api/v1/marcellus/cowork"


def _identity(sub: str = "cowork-owner", tenant_id: str = "global", role: str = "admin") -> dict:
    return {
        "id": sub,
        "sub": sub,
        "email": f"{sub}@example.invalid",
        "role": role,
        "tenant_id": tenant_id,
    }


def _use_identity(identity: dict) -> None:
    app.dependency_overrides[get_current_user] = lambda: identity


def _gateway_response(text: str = "Done") -> dict:
    return {
        "status": "completed",
        "response": text,
        "source": "profile:ollama_local_fallback",
        "provider": "ollama",
        "model": "qwen2.5:7b",
        "mode": "cowork",
        "governance": {
            "outcome": "allowed",
            "policy_name": "Test policy",
            "reason": "Allowed",
            "risk_score": 0,
            "data_classification": "internal",
            "input_redacted": False,
            "output_redacted": False,
            "injection_risk": False,
            "injection_vectors": [],
        },
        "votes": [],
        "confidence": 0.9,
        "agreement": "high",
        "latency_ms": 2,
    }


@pytest.fixture(autouse=True)
def _inline_runner(db_session):
    """Run job runners inline on the test session so assertions see settled state."""

    class _Factory:
        def __call__(self):
            return self

        async def __aenter__(self):
            return db_session

        async def __aexit__(self, *_exc):
            return False

    jobs.configure_runner(_Factory(), inline=True)
    yield
    jobs.reset_runner()


async def _project(client, name="Cowork project") -> dict:
    response = await client.post(
        f"{BASE}/projects",
        json={"tenant_id": "global", "name": name, "classification": "internal"},
    )
    assert response.status_code == 200, response.text
    return response.json()


async def _conversation(client, project_id: str | None) -> dict:
    response = await client.post(
        f"{BASE}/conversations",
        json={
            "tenant_id": "global",
            "project_id": project_id,
            "title": "Cowork",
            "mode": "cowork",
            "classification": "internal",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


# --------------------------------------------------------------------------
# State machine
# --------------------------------------------------------------------------


def test_state_machine_covers_the_contract_vocabulary():
    required = {
        "queued", "planning", "context_compiling", "waiting_for_brain",
        "brain_streaming", "inspecting_workspace", "writing_files",
        "awaiting_approval", "running_command", "running_tests", "debugging",
        "verifying", "completed", "failed", "cancelled", "timed_out",
        "needs_user_input",
    }
    assert states.ALL_STATES == required


def test_terminal_states_are_final_and_illegal_jumps_refused():
    assert not states.can_transition("completed", "planning")
    assert not states.can_transition("queued", "verifying")
    # Failure/cancellation may interrupt any live state.
    assert states.can_transition("running_tests", "cancelled")
    assert states.can_transition("brain_streaming", "failed")


def test_completion_outcome_never_reports_unverified_as_verified():
    assert states.completion_outcome(verified=False, had_failures=False) == "completed_unverified"
    assert states.completion_outcome(verified=True, had_failures=False) == "completed_verified"
    assert states.completion_outcome(verified=True, had_failures=True) == "completed_with_failures"


# --------------------------------------------------------------------------
# Command safety
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "npm test; rm -rf /",
        "pytest && curl http://evil.invalid",
        "npm test | sh",
        "pytest `whoami`",
        "npm test $(cat /etc/passwd)",
        "pytest > /etc/hosts",
        "npm test\nrm file",
        "bash -c 'echo hi'",
        "sh script.sh",
        "curl http://example.invalid",
    ],
)
def test_command_injection_and_chaining_are_rejected(command):
    assert is_command_safe(command) is False


@pytest.mark.parametrize("command", ["npm test --silent", "pytest -q", "go test ./...", "cargo test"])
def test_allowlisted_commands_parse_to_argv(command):
    program, argv = executors.parse_command(command)
    assert program in executors.ALLOWED_PROGRAMS
    assert isinstance(argv, list)


def test_parse_command_rejects_unknown_program():
    with pytest.raises(executors.CommandRejected):
        executors.parse_command("rustc main.rs")


def test_output_redaction_removes_secrets():
    leaked = "Running tests\nAWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLEKEYVALUE1234567890ab\ndone"
    cleaned = redact_output(leaked)
    assert "AKIAIOSFODNN7EXAMPLEKEYVALUE1234567890ab" not in cleaned


# --------------------------------------------------------------------------
# Executor selection
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_auto_prefers_local_then_codex(monkeypatch):
    monkeypatch.setattr(executors, "bridge_configured", lambda: True)
    executor, availability = await executors.resolve_executor("auto", token="tok")
    assert executor.name == executors.LOCAL
    assert availability.available is True


@pytest.mark.asyncio
async def test_auto_reports_unavailable_when_nothing_is_connected(monkeypatch):
    monkeypatch.setattr(executors, "bridge_configured", lambda: False)
    executor, availability = await executors.resolve_executor("auto", token=None)
    assert executor is None
    assert availability.executor == executors.NONE


@pytest.mark.asyncio
async def test_explicit_codex_never_silently_switches_to_local(monkeypatch):
    # Bridge down => Codex unavailable. An explicit Codex request must report
    # that rather than quietly running locally.
    monkeypatch.setattr(executors, "bridge_configured", lambda: False)
    executor, availability = await executors.resolve_executor("codex_app_server", token="tok")
    assert executor is None
    assert availability.executor == executors.CODEX


@pytest.mark.asyncio
async def test_explicit_local_never_silently_switches_to_codex(monkeypatch):
    monkeypatch.setattr(executors, "bridge_configured", lambda: False)
    executor, availability = await executors.resolve_executor("enkstein_local", token="tok")
    assert executor is None
    assert availability.executor == executors.LOCAL


@pytest.mark.asyncio
async def test_local_unavailable_without_approved_root(monkeypatch):
    monkeypatch.setattr(executors, "bridge_configured", lambda: True)
    availability = await executors.LocalExecutor().availability(token=None)
    assert availability.available is False
    assert "folder" in availability.reason.lower()


@pytest.mark.asyncio
async def test_auto_falls_back_to_codex_when_local_has_no_root(monkeypatch):
    """Codex stays optional, but it is still a real fallback under Auto.

    A project folder is approved (both executors require one -- there is nowhere
    safe to run without it), but the local desktop runtime itself is down. Auto
    must then reach Codex rather than reporting that nothing can run.
    """
    monkeypatch.setattr(executors, "bridge_configured", lambda: True)

    async def local_down(*, token, project_selected=True):
        return executors.ExecutorAvailability(
            executors.LOCAL, False, "The desktop runtime is not connected."
        )

    monkeypatch.setattr(executors._LOCAL, "availability", local_down)
    executor, availability = await executors.resolve_executor("auto", token="tok")
    assert executor is not None
    assert executor.name == executors.CODEX
    assert availability.available is True


@pytest.mark.asyncio
async def test_no_selected_project_is_not_reported_as_a_folderless_project(monkeypatch):
    """Cowork with nothing open must not blame the project.

    Telling an operator who has no project selected that "this project has no
    folder connected" names a problem they cannot act on and reads as a broken
    executor. The two states have different remedies and must read differently.
    """
    monkeypatch.setattr(executors, "bridge_configured", lambda: True)
    report = await executors.availability_report(None, project_selected=False)
    assert [item["available"] for item in report] == [False, False]
    for item in report:
        assert item["reason"] == executors.NO_PROJECT_REASON
        assert "this project" not in item["reason"].lower()


@pytest.mark.asyncio
async def test_folderless_project_states_the_remedy(monkeypatch):
    monkeypatch.setattr(executors, "bridge_configured", lambda: True)
    report = await executors.availability_report(None, project_selected=True)
    for item in report:
        assert item["available"] is False
        assert item["reason"] == executors.NO_BINDING_REASON
        assert "import folder" in item["reason"].lower()


@pytest.mark.asyncio
async def test_auto_reports_the_missing_folder_rather_than_a_generic_failure(monkeypatch):
    """Auto's summary must carry the actionable reason, not swallow it."""
    monkeypatch.setattr(executors, "bridge_configured", lambda: True)
    executor, availability = await executors.resolve_executor(
        "auto", token=None, project_selected=True
    )
    assert executor is None
    assert availability.executor == executors.NONE
    assert availability.reason == executors.NO_BINDING_REASON


@pytest.mark.asyncio
async def test_auto_still_reports_a_down_runtime_generically(monkeypatch):
    """A folder is approved but the host runtime is down: that is not a folder
    problem, so it must not be described as one."""
    monkeypatch.setattr(executors, "bridge_configured", lambda: False)
    executor, availability = await executors.resolve_executor(
        "auto", token="tok", project_selected=True
    )
    assert executor is None
    assert availability.reason == "No governed executor is connected."


@pytest.mark.asyncio
async def test_executor_route_distinguishes_no_project_from_no_folder(client, monkeypatch):
    """The Cowork picker needs both facts to explain itself.

    ``project_selected`` lets the UI say "pick a project" instead of implying a
    project is misconfigured, and ``needs_folder`` is what lets it offer the fix
    rather than only naming the problem.
    """
    from app.core.marcellus import cowork_routes

    monkeypatch.setattr(executors, "bridge_configured", lambda: True)
    monkeypatch.setattr(cowork_routes, "bridge_configured", lambda: True)
    monkeypatch.setattr(cowork_routes, "get_binding", lambda *_args, **_kwargs: None)

    response = await client.get("/api/v1/marcellus/cowork/executors")
    assert response.status_code == 200
    body = response.json()
    assert body["project_selected"] is False
    assert body["needs_folder"] is False
    assert body["executors"][0]["reason"] == executors.NO_PROJECT_REASON

    scoped = await client.get(
        "/api/v1/marcellus/cowork/executors",
        params={"project_id": str(uuid.uuid4())},
    )
    assert scoped.status_code == 200
    scoped_body = scoped.json()
    assert scoped_body["project_selected"] is True
    assert scoped_body["needs_folder"] is True
    assert scoped_body["executors"][0]["reason"] == executors.NO_BINDING_REASON


@pytest.mark.asyncio
async def test_executor_route_does_not_offer_a_folder_fix_when_the_runtime_is_down(
    client, monkeypatch
):
    """Approving a folder cannot help when the desktop bridge is absent, so the
    UI must not be told to offer that as the remedy."""
    from app.core.marcellus import cowork_routes

    monkeypatch.setattr(executors, "bridge_configured", lambda: False)
    monkeypatch.setattr(cowork_routes, "bridge_configured", lambda: False)
    monkeypatch.setattr(cowork_routes, "get_binding", lambda *_args, **_kwargs: None)

    response = await client.get(
        "/api/v1/marcellus/cowork/executors",
        params={"project_id": str(uuid.uuid4())},
    )
    assert response.status_code == 200
    assert response.json()["needs_folder"] is False


# --------------------------------------------------------------------------
# The runner must not reference names that do not exist
# --------------------------------------------------------------------------


def test_runner_has_no_undefined_names():
    """Every global the runner reads must actually resolve.

    ``run_job`` called ``_record_progress`` -- a function that was never
    defined -- from the Brain progress callback. Nothing imported the module in
    a test and the name only resolves when a Brain reports progress, so it
    reached main as a latent NameError on real Cowork jobs. This walks the
    module for loaded globals instead of exercising one path, so the whole file
    is covered rather than the one line that happened to break.
    """
    import ast
    import builtins
    import inspect

    from app.core.marcellus import cowork_runner

    tree = ast.parse(inspect.getsource(cowork_runner))
    bound: set[str] = set(dir(builtins)) | set(vars(cowork_runner))
    for node in ast.walk(tree):
        # Locals, parameters, and comprehension targets are bound at runtime and
        # are not resolvable from module globals, so collect them as legitimate.
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            bound.add(node.name)
            args = node.args
            for arg in [*args.args, *args.posonlyargs, *args.kwonlyargs]:
                bound.add(arg.arg)
            if args.vararg:
                bound.add(args.vararg.arg)
            if args.kwarg:
                bound.add(args.kwarg.arg)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bound.add(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bound.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            # Function-local imports (used here to break an import cycle with
            # workspace) bind names that never appear in module globals.
            for alias in node.names:
                bound.add((alias.asname or alias.name).split(".", 1)[0])

    undefined = sorted(
        {
            node.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id not in bound
        }
    )
    assert undefined == [], f"cowork_runner references undefined names: {undefined}"


# --------------------------------------------------------------------------
# Isolation posture must be reported honestly per platform
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_macos_sandbox_posture_is_reported(monkeypatch):
    monkeypatch.setattr(executors, "bridge_configured", lambda: True)

    async def fake_invoke(operation, payload):
        return {
            "available": True, "exit_code": 0, "output": "ok", "sandboxed": True,
            "isolation": "sandbox",
            "isolation_detail": "Seatbelt profile: network denied; reads and writes confined to the approved project root.",
            "execution_id": "e-mac",
        }

    monkeypatch.setattr(executors, "invoke_native_workspace", fake_invoke)
    result = await executors.LocalExecutor().execute_command(command="pytest -q", token="tok")
    assert result.isolation == "sandbox"
    assert "network denied" in result.isolation_detail


@pytest.mark.asyncio
async def test_windows_is_reported_as_containment_not_sandbox(monkeypatch):
    """Windows has no seatbelt equivalent, so it must never claim "sandbox".

    It provides Job Object tree termination, argv-only execution, a cleared
    environment, and a root-pinned cwd -- real containment, but reads outside
    the root and network access are not restricted.
    """
    monkeypatch.setattr(executors, "bridge_configured", lambda: True)

    async def fake_invoke(operation, payload):
        return {
            "available": True, "exit_code": 0, "output": "ok", "sandboxed": False,
            "isolation": "containment",
            "isolation_detail": "Reads outside the approved root and network access are NOT restricted on this platform.",
            "execution_id": "e-win",
        }

    monkeypatch.setattr(executors, "invoke_native_workspace", fake_invoke)
    result = await executors.LocalExecutor().execute_command(command="pytest -q", token="tok")
    assert result.sandboxed is False
    assert result.isolation == "containment"
    assert "NOT restricted" in result.isolation_detail


@pytest.mark.asyncio
async def test_missing_isolation_field_defaults_to_the_weaker_claim(monkeypatch):
    """An older broker that predates the field must not be treated as sandboxed."""
    monkeypatch.setattr(executors, "bridge_configured", lambda: True)

    async def fake_invoke(operation, payload):
        return {"available": True, "exit_code": 0, "output": "ok", "execution_id": "e-old"}

    monkeypatch.setattr(executors, "invoke_native_workspace", fake_invoke)
    result = await executors.LocalExecutor().execute_command(command="pytest -q", token="tok")
    assert result.isolation == "containment"

# --------------------------------------------------------------------------
# Local executor behaviour (bridge stubbed)
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_local_command_passes(monkeypatch):
    monkeypatch.setattr(executors, "bridge_configured", lambda: True)

    async def fake_invoke(operation, payload):
        assert operation == "exec"
        assert payload["program"] == "pytest"
        # argv is passed through as a list, never a shell string.
        assert payload["arguments"] == ["-q"]
        assert payload["execution_id"]
        return {"available": True, "exit_code": 0, "output": "2 passed", "sandboxed": True,
                "duration_ms": 120, "execution_id": payload["execution_id"]}

    monkeypatch.setattr(executors, "invoke_native_workspace", fake_invoke)
    result = await executors.LocalExecutor().execute_command(command="pytest -q", token="tok")
    assert result.status == executors.PASSED
    assert result.sandboxed is True
    assert result.execution_id


@pytest.mark.asyncio
async def test_local_command_fails(monkeypatch):
    monkeypatch.setattr(executors, "bridge_configured", lambda: True)

    async def fake_invoke(operation, payload):
        return {"available": True, "exit_code": 1, "output": "1 failed", "execution_id": "e1"}

    monkeypatch.setattr(executors, "invoke_native_workspace", fake_invoke)
    result = await executors.LocalExecutor().execute_command(command="pytest -q", token="tok")
    assert result.status == executors.FAILED
    assert result.exit_code == 1


@pytest.mark.asyncio
async def test_local_command_timeout_is_not_a_pass(monkeypatch):
    monkeypatch.setattr(executors, "bridge_configured", lambda: True)

    async def fake_invoke(operation, payload):
        return {"available": True, "exit_code": 15, "timed_out": True, "output": "", "execution_id": "e2"}

    monkeypatch.setattr(executors, "invoke_native_workspace", fake_invoke)
    result = await executors.LocalExecutor().execute_command(command="pytest -q", token="tok")
    assert result.status == executors.FAILED
    assert result.timed_out is True


@pytest.mark.asyncio
async def test_local_command_cancel_targets_execution_id(monkeypatch):
    monkeypatch.setattr(executors, "bridge_configured", lambda: True)
    seen: dict = {}

    async def fake_invoke(operation, payload):
        seen["operation"] = operation
        seen["payload"] = payload
        return {"cancelled": True}

    monkeypatch.setattr(executors, "invoke_native_workspace", fake_invoke)
    ok = await executors.LocalExecutor().cancel(execution_id="exec-123")
    assert ok is True
    assert seen["operation"] == "exec_cancel"
    assert seen["payload"] == {"execution_id": "exec-123"}


@pytest.mark.asyncio
async def test_local_executor_rejects_injection_before_reaching_the_broker(monkeypatch):
    monkeypatch.setattr(executors, "bridge_configured", lambda: True)
    called = False

    async def fake_invoke(operation, payload):
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(executors, "invoke_native_workspace", fake_invoke)
    result = await executors.LocalExecutor().execute_command(
        command="npm test; curl http://evil.invalid", token="tok"
    )
    assert result.status == executors.DENIED
    assert called is False


# --------------------------------------------------------------------------
# Command detection
# --------------------------------------------------------------------------


def test_detection_is_manifest_driven():
    class _Inspection:
        manifests = {"package.json": '{"scripts": {"test": "jest", "lint": "eslint ."}}'}

    plans = detect_commands(_Inspection())
    kinds = {plan.kind for plan in plans}
    assert "test" in kinds and "lint" in kinds
    assert all(is_command_safe(plan.command) for plan in plans)


def test_python_project_is_not_given_npm_commands():
    class _Inspection:
        manifests = {"pyproject.toml": "[tool.pytest.ini_options]\naddopts = '-q'"}

    plans = detect_commands(_Inspection())
    assert plans and all("npm" not in plan.command for plan in plans)


def test_unknown_project_yields_no_commands():
    class _Inspection:
        manifests = {}

    assert detect_commands(_Inspection()) == []


def test_failure_capsule_is_bounded_and_scoped():
    from app.core.marcellus.cowork_commands import CommandOutcome

    outcome = CommandOutcome("test", "pytest -q", "failed", exit_code=1, summary="x" * 9000)
    capsule = failure_capsule([outcome], approved_paths=["src/app.py"])
    assert len(capsule) < 4000
    assert "src/app.py" in capsule


@pytest.mark.asyncio
async def test_run_command_without_executor_is_not_run_not_passed():
    outcome = await run_command(plan=CommandPlan("test", "pytest -q", "r"), executor=None, token=None)
    assert outcome.status == executors.NOT_RUN
    assert outcome.status != executors.PASSED


def test_verification_report_requires_a_real_pass():
    from app.core.marcellus.cowork_commands import CommandOutcome

    report = VerificationReport()
    for status in (executors.UNAVAILABLE, executors.DENIED, executors.SKIPPED, executors.NOT_RUN):
        report.outcomes.append(CommandOutcome("test", "pytest -q", status))
    assert report.verified is False
    report.outcomes.append(CommandOutcome("test", "pytest -q", executors.PASSED))
    assert report.verified is True
