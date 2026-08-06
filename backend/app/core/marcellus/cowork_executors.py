"""Provider-independent execution contract for Cowork.

Cowork separates two roles that used to be conflated:

* a **Brain** plans, researches, and authors content. It may be a browser
  session, Ollama, an API provider, a subscription CLI, or a custom swarm. It
  never touches the filesystem.
* an **Executor** performs real work in the approved project root: commands,
  tests, builds, and verification.

Any Brain composes with any Executor. Codex is *one* executor among others and
is never required; the desktop default is the Enkstein Local Executor, which
runs allowlisted programs through the native broker's narrowly scoped exec
operation. When no executor is connected the result is reported as
``unavailable`` -- never as a pass.

File writes are deliberately not part of this contract: they remain the
exclusive responsibility of the deterministic governed writer.
"""

from __future__ import annotations

import logging
import shlex
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol

from app.core.modelclaw.brain_bridge import (
    bridge_configured,
    invoke_codex_bridge,
    invoke_native_workspace,
)

logger = logging.getLogger("marcellus.cowork.executors")


#: Verification outcome vocabulary. Only ``PASSED`` counts as verification.
PASSED = "passed"
FAILED = "failed"
DENIED = "denied"
UNAVAILABLE = "unavailable"
SKIPPED = "skipped"
NOT_RUN = "not_run"

SUCCESS_STATUSES = frozenset({PASSED})
#: Statuses that must never be mistaken for a successful verification.
NON_VERIFYING_STATUSES = frozenset({FAILED, DENIED, UNAVAILABLE, SKIPPED, NOT_RUN})


#: Executor identifiers surfaced to the operator and stored on the job.
LOCAL = "enkstein_local"
CODEX = "codex_app_server"
AUTO = "auto"
NONE = "unavailable"

EXECUTOR_LABELS = {
    LOCAL: "Enkstein Local Runtime",
    CODEX: "Codex App Server",
    NONE: "unavailable",
    AUTO: "Auto",
}

#: Why an executor is not usable right now. These are distinct situations with
#: distinct remedies, and collapsing them into one string is what made the
#: picker read as broken: an operator with no project open was told their
#: project had no folder, and an operator on a folderless project was never
#: told that connecting a folder is the fix.
NO_PROJECT_REASON = (
    "Select a Cowork project first. Executors run inside an approved project folder."
)
NO_BINDING_REASON = (
    "This project has no local folder connected. Use Import folder in the "
    "Project files panel to approve one."
)


def binding_reason(*, project_selected: bool) -> str:
    """Reason text for a missing folder binding, specific to the situation."""

    return NO_BINDING_REASON if project_selected else NO_PROJECT_REASON


@dataclass
class ExecutorCapabilities:
    executor: str
    label: str
    can_run_commands: bool
    can_cancel: bool
    can_inspect: bool
    #: Programs this executor is willing to run, for UI/diagnostics.
    allowed_programs: tuple[str, ...] = ()

    def as_payload(self) -> dict[str, Any]:
        return {
            "executor": self.executor,
            "label": self.label,
            "can_run_commands": self.can_run_commands,
            "can_cancel": self.can_cancel,
            "can_inspect": self.can_inspect,
            "allowed_programs": list(self.allowed_programs),
        }


@dataclass
class ExecutorAvailability:
    executor: str
    available: bool
    reason: str = ""

    def as_payload(self) -> dict[str, Any]:
        return {
            "executor": self.executor,
            "label": EXECUTOR_LABELS.get(self.executor, self.executor),
            "available": self.available,
            "reason": self.reason,
        }


@dataclass
class ExecutionResult:
    """Outcome of one command. ``status`` uses the vocabulary above."""

    status: str
    exit_code: int | None = None
    output: str = ""
    truncated: bool = False
    duration_ms: int | None = None
    timed_out: bool = False
    detail: str = ""
    executor: str = NONE
    #: Durable identifier for this execution, so it can be cancelled by id even
    #: after the request that started it is gone.
    execution_id: str = ""
    cancelled: bool = False
    sandboxed: bool = False
    #: Platform isolation posture reported by the native broker. macOS returns
    #: "sandbox" (seatbelt: network denied, reads/writes confined to the approved
    #: root). Windows returns "containment" (Job Object tree kill, argv-only
    #: execution, cleared environment, root-pinned cwd) because it does not
    #: restrict reads outside the root or block network. Surfaced verbatim so an
    #: operator is never told a run was sandboxed when it was only contained.
    isolation: str = "unknown"
    isolation_detail: str = ""
    events: list[dict[str, Any]] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.status == PASSED


#: Programs an executor may run. Interpreters that would re-enable arbitrary
#: execution are intentionally excluded.
ALLOWED_PROGRAMS: tuple[str, ...] = (
    "npm", "npx", "pnpm", "yarn", "node",
    "pytest", "python3", "ruff",
    "go", "cargo", "make", "tsc", "eslint",
)

#: Bounded output returned to callers. Matches the broker's own ceiling.
MAX_OUTPUT_CHARS = 20_000
DEFAULT_TIMEOUT_SECONDS = 300


class CommandRejected(ValueError):
    """A command failed validation before any executor was contacted."""


def parse_command(command: str) -> tuple[str, list[str]]:
    """Split a command into ``(program, argv)`` with no shell semantics.

    ``shlex`` is used in POSIX mode purely to tokenize quoted arguments; the
    result is passed as argv, so shell operators are never interpreted. Any
    metacharacter is rejected outright rather than quoted, because a legitimate
    detected command never needs one.
    """
    candidate = (command or "").strip()
    if not candidate or len(candidate) > 300:
        raise CommandRejected("Command is empty or too long")
    for marker in (";", "&", "|", "`", "$", ">", "<", "\n", "\r", "&&", "||"):
        if marker in candidate:
            raise CommandRejected("Command contains shell control characters")
    try:
        tokens = shlex.split(candidate)
    except ValueError as exc:
        raise CommandRejected("Command could not be parsed") from exc
    if not tokens:
        raise CommandRejected("Command is empty")
    program, *arguments = tokens
    if program not in ALLOWED_PROGRAMS:
        raise CommandRejected(f"Program '{program}' is not allowlisted")
    if len(arguments) > 24:
        raise CommandRejected("Too many arguments")
    return program, arguments


class Executor(Protocol):
    """Contract every Cowork executor implements."""

    name: str

    def capabilities(self) -> ExecutorCapabilities: ...

    async def availability(
        self, *, token: str | None, project_selected: bool = True
    ) -> ExecutorAvailability: ...

    async def execute_command(
        self, *, command: str, token: str | None, scope_digest: str, timeout_seconds: int
    ) -> ExecutionResult: ...

    async def cancel(self, *, execution_id: str, token: str | None, scope_digest: str) -> bool: ...


class LocalExecutor:
    """Runs allowlisted programs in the approved root via the native broker.

    The broker enforces containment, the allowlist, symlink rejection, output
    bounds, and the timeout independently of this class, so a bug here cannot
    widen the sandbox.
    """

    name = LOCAL

    def capabilities(self) -> ExecutorCapabilities:
        return ExecutorCapabilities(
            executor=LOCAL,
            label=EXECUTOR_LABELS[LOCAL],
            can_run_commands=True,
            can_cancel=True,
            can_inspect=True,
            allowed_programs=ALLOWED_PROGRAMS,
        )

    async def availability(
        self, *, token: str | None, project_selected: bool = True
    ) -> ExecutorAvailability:
        if not bridge_configured():
            return ExecutorAvailability(
                LOCAL, False, "The Enkstein desktop runtime is not connected on this host."
            )
        if not token:
            return ExecutorAvailability(
                LOCAL, False, binding_reason(project_selected=project_selected)
            )
        return ExecutorAvailability(LOCAL, True, "")

    async def execute_command(
        self,
        *,
        command: str,
        token: str | None,
        scope_digest: str = "",
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        execution_id: str | None = None,
    ) -> ExecutionResult:
        identifier = execution_id or uuid.uuid4().hex
        try:
            program, arguments = parse_command(command)
        except CommandRejected as exc:
            return ExecutionResult(
                status=DENIED, detail=str(exc), executor=LOCAL, execution_id=identifier
            )
        availability = await self.availability(token=token)
        if not availability.available:
            return ExecutionResult(
                status=UNAVAILABLE,
                detail=availability.reason,
                executor=LOCAL,
                execution_id=identifier,
            )
        try:
            body = await invoke_native_workspace(
                "exec",
                {
                    "token": token,
                    "program": program,
                    "arguments": arguments,
                    "timeout_seconds": int(timeout_seconds),
                    "execution_id": identifier,
                },
            )
        except Exception:
            # Never log the command output or the token.
            logger.warning("Local executor invocation failed: program=%s", program)
            return ExecutionResult(
                status=UNAVAILABLE,
                detail="The Enkstein desktop runtime did not respond.",
                executor=LOCAL,
                execution_id=identifier,
            )
        if body.get("available") is False:
            return ExecutionResult(
                status=UNAVAILABLE,
                detail=str(body.get("detail") or "The program is not installed on this host."),
                executor=LOCAL,
                execution_id=identifier,
            )
        exit_code = body.get("exit_code")
        try:
            exit_code = int(exit_code) if exit_code is not None else None
        except (TypeError, ValueError):
            exit_code = None
        timed_out = bool(body.get("timed_out"))
        cancelled = bool(body.get("cancelled"))
        output = str(body.get("output") or "")[:MAX_OUTPUT_CHARS]
        if timed_out:
            detail = "The command exceeded its time limit."
        elif cancelled:
            detail = "The command was cancelled."
        else:
            detail = ""
        return ExecutionResult(
            status=PASSED if (not timed_out and not cancelled and exit_code == 0) else FAILED,
            exit_code=exit_code,
            output=output,
            truncated=bool(body.get("truncated")),
            duration_ms=body.get("duration_ms"),
            timed_out=timed_out,
            cancelled=cancelled,
            sandboxed=bool(body.get("sandboxed")),
            # Trust the broker's own report; default to the weaker claim when a
            # host predates this field so we never overstate isolation.
            isolation=str(body.get("isolation") or ("sandbox" if body.get("sandboxed") else "containment")),
            isolation_detail=str(body.get("isolation_detail") or ""),
            detail=detail,
            executor=LOCAL,
            execution_id=str(body.get("execution_id") or identifier),
        )

    async def cancel(
        self, *, execution_id: str = "", token: str | None = None, scope_digest: str = ""
    ) -> bool:
        """Terminate a live execution and its entire process tree.

        The broker signals the process *group* (macOS) or terminates the Job
        Object (Windows), so a test runner's own children are reaped too rather
        than surviving as orphans holding the project root.
        """
        if not execution_id or not bridge_configured():
            return False
        try:
            body = await invoke_native_workspace("exec_cancel", {"execution_id": execution_id})
        except Exception:
            logger.warning("Local executor cancellation failed")
            return False
        return bool(body.get("cancelled"))


class CodexExecutor:
    """Optional executor backed by a supervised Codex App Server session."""

    name = CODEX

    def capabilities(self) -> ExecutorCapabilities:
        return ExecutorCapabilities(
            executor=CODEX,
            label=EXECUTOR_LABELS[CODEX],
            can_run_commands=True,
            can_cancel=True,
            can_inspect=True,
            allowed_programs=ALLOWED_PROGRAMS,
        )

    async def availability(
        self, *, token: str | None, project_selected: bool = True
    ) -> ExecutorAvailability:
        if not bridge_configured():
            return ExecutorAvailability(
                CODEX, False, "The Codex App Server is not connected on this host."
            )
        if not token:
            return ExecutorAvailability(
                CODEX, False, binding_reason(project_selected=project_selected)
            )
        return ExecutorAvailability(CODEX, True, "")

    async def execute_command(
        self,
        *,
        command: str,
        token: str | None,
        scope_digest: str = "",
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        execution_id: str | None = None,
    ) -> ExecutionResult:
        identifier = execution_id or uuid.uuid4().hex
        try:
            parse_command(command)
        except CommandRejected as exc:
            return ExecutionResult(
                status=DENIED, detail=str(exc), executor=CODEX, execution_id=identifier
            )
        availability = await self.availability(token=token)
        if not availability.available:
            return ExecutionResult(
                status=UNAVAILABLE,
                detail=availability.reason,
                executor=CODEX,
                execution_id=identifier,
            )
        try:
            body = await invoke_codex_bridge(
                "turn",
                {
                    "token": token,
                    "scope_digest": scope_digest,
                    "prompt": f"Run the command `{command}` and report its exit code and a short summary.",
                },
            )
        except Exception:
            logger.warning("Codex executor invocation failed")
            return ExecutionResult(
                status=UNAVAILABLE,
                detail="The Codex App Server did not respond.",
                executor=CODEX,
            )
        exit_code = body.get("exit_code")
        try:
            exit_code = int(exit_code) if exit_code is not None else None
        except (TypeError, ValueError):
            exit_code = None
        output = str(body.get("summary") or body.get("output") or "")[:MAX_OUTPUT_CHARS]
        if exit_code is None:
            status_value = PASSED if body.get("success") else FAILED
        else:
            status_value = PASSED if exit_code == 0 else FAILED
        return ExecutionResult(
            status=status_value,
            exit_code=exit_code,
            output=output,
            executor=CODEX,
            execution_id=identifier,
        )

    async def cancel(
        self, *, execution_id: str = "", token: str | None = None, scope_digest: str = ""
    ) -> bool:
        try:
            await invoke_codex_bridge("cancel", {"token": token, "scope_digest": scope_digest})
            return True
        except Exception:
            logger.warning("Codex executor cancellation failed")
            return False


_LOCAL = LocalExecutor()
_CODEX = CodexExecutor()

REGISTRY: dict[str, Any] = {LOCAL: _LOCAL, CODEX: _CODEX}


def get_executor(name: str):
    return REGISTRY.get(name)


async def resolve_executor(
    preference: str, *, token: str | None, project_selected: bool = True
) -> tuple[Any | None, ExecutorAvailability]:
    """Pick the executor for a job.

    Auto prefers the local desktop runtime and falls back to Codex, so a desktop
    user gets real execution without configuring anything and a host with only
    Codex still works. An explicit choice is honoured as written -- if the
    operator asked for Codex and Codex is down, that is reported rather than
    silently rerouted.
    """
    requested = (preference or AUTO).strip() or AUTO
    if requested in {LOCAL, CODEX}:
        executor = REGISTRY[requested]
        availability = await executor.availability(
            token=token, project_selected=project_selected
        )
        return (executor if availability.available else None), availability
    if requested == NONE:
        return None, ExecutorAvailability(NONE, False, "Execution was disabled for this job.")

    local_availability = await _LOCAL.availability(
        token=token, project_selected=project_selected
    )
    if local_availability.available:
        return _LOCAL, local_availability
    codex_availability = await _CODEX.availability(
        token=token, project_selected=project_selected
    )
    if codex_availability.available:
        return _CODEX, codex_availability
    # When nothing is connected because no folder is approved, say the thing the
    # operator can act on rather than the generic "no executor" line.
    if not token:
        return None, ExecutorAvailability(
            NONE, False, binding_reason(project_selected=project_selected)
        )
    return None, ExecutorAvailability(
        NONE,
        False,
        "No governed executor is connected.",
    )


async def availability_report(
    token: str | None, *, project_selected: bool = True
) -> list[dict[str, Any]]:
    return [
        (
            await _LOCAL.availability(token=token, project_selected=project_selected)
        ).as_payload(),
        (
            await _CODEX.availability(token=token, project_selected=project_selected)
        ).as_payload(),
    ]
