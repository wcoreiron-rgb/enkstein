"""Canonical Cowork job lifecycle.

The state set is fixed by the Cowork contract; a job may only ever hold one of
these values, and only the transitions declared here are permitted. Keeping the
machine in one small module means the coordinator, the routes, and the tests all
agree on what "running" means without each re-deriving it.
"""

from __future__ import annotations


QUEUED = "queued"
PLANNING = "planning"
CONTEXT_COMPILING = "context_compiling"
WAITING_FOR_BRAIN = "waiting_for_brain"
BRAIN_STREAMING = "brain_streaming"
INSPECTING_WORKSPACE = "inspecting_workspace"
WRITING_FILES = "writing_files"
AWAITING_APPROVAL = "awaiting_approval"
RUNNING_COMMAND = "running_command"
RUNNING_TESTS = "running_tests"
DEBUGGING = "debugging"
VERIFYING = "verifying"
COMPLETED = "completed"
FAILED = "failed"
CANCELLED = "cancelled"
TIMED_OUT = "timed_out"
NEEDS_USER_INPUT = "needs_user_input"

ALL_STATES: frozenset[str] = frozenset(
    {
        QUEUED,
        PLANNING,
        CONTEXT_COMPILING,
        WAITING_FOR_BRAIN,
        BRAIN_STREAMING,
        INSPECTING_WORKSPACE,
        WRITING_FILES,
        AWAITING_APPROVAL,
        RUNNING_COMMAND,
        RUNNING_TESTS,
        DEBUGGING,
        VERIFYING,
        COMPLETED,
        FAILED,
        CANCELLED,
        TIMED_OUT,
        NEEDS_USER_INPUT,
    }
)

#: A job in a terminal state is never advanced again; only ``retry``/``resume``
#: may move it, and only by creating a fresh attempt.
TERMINAL_STATES: frozenset[str] = frozenset({COMPLETED, FAILED, CANCELLED, TIMED_OUT})

#: States that legitimately wait on a human. These are *not* terminal, and the
#: coordinator must not time them out on the provider clock.
SUSPENDED_STATES: frozenset[str] = frozenset({AWAITING_APPROVAL, NEEDS_USER_INPUT})

#: States where work is genuinely in flight.
ACTIVE_STATES: frozenset[str] = frozenset(ALL_STATES - TERMINAL_STATES - SUSPENDED_STATES)

#: Any in-flight or suspended state may fail, be cancelled, or time out, so the
#: table below lists only the forward/progress edges and terminal edges are
#: granted implicitly by :func:`can_transition`.
_FORWARD: dict[str, frozenset[str]] = {
    QUEUED: frozenset({PLANNING, INSPECTING_WORKSPACE, CONTEXT_COMPILING}),
    PLANNING: frozenset({INSPECTING_WORKSPACE, CONTEXT_COMPILING, WAITING_FOR_BRAIN, NEEDS_USER_INPUT}),
    INSPECTING_WORKSPACE: frozenset({CONTEXT_COMPILING, PLANNING, WAITING_FOR_BRAIN}),
    CONTEXT_COMPILING: frozenset({WAITING_FOR_BRAIN, NEEDS_USER_INPUT}),
    WAITING_FOR_BRAIN: frozenset({BRAIN_STREAMING, WRITING_FILES, VERIFYING, NEEDS_USER_INPUT}),
    BRAIN_STREAMING: frozenset({WRITING_FILES, AWAITING_APPROVAL, VERIFYING, DEBUGGING, NEEDS_USER_INPUT}),
    AWAITING_APPROVAL: frozenset({WRITING_FILES, VERIFYING, RUNNING_COMMAND}),
    WRITING_FILES: frozenset({RUNNING_COMMAND, RUNNING_TESTS, VERIFYING, AWAITING_APPROVAL, DEBUGGING}),
    RUNNING_COMMAND: frozenset({RUNNING_TESTS, VERIFYING, DEBUGGING, AWAITING_APPROVAL}),
    RUNNING_TESTS: frozenset({VERIFYING, DEBUGGING, WRITING_FILES}),
    DEBUGGING: frozenset({WRITING_FILES, RUNNING_COMMAND, RUNNING_TESTS, VERIFYING, WAITING_FOR_BRAIN}),
    VERIFYING: frozenset({COMPLETED, DEBUGGING, WRITING_FILES}),
    NEEDS_USER_INPUT: frozenset({PLANNING, CONTEXT_COMPILING, WAITING_FOR_BRAIN, WRITING_FILES}),
}


def is_terminal(state: str) -> bool:
    return state in TERMINAL_STATES


def can_transition(current: str, target: str) -> bool:
    """Return whether ``current`` -> ``target`` is a legal job transition."""
    if current not in ALL_STATES or target not in ALL_STATES:
        return False
    if current in TERMINAL_STATES:
        return False
    if target in TERMINAL_STATES:
        # Failure, cancellation, and timeout can interrupt any live state.
        return True
    return target in _FORWARD.get(current, frozenset())


#: Explicit outcome recorded alongside the terminal state, so "completed" alone
#: can never be read as "verified". A job that wrote files but ran no command is
#: ``completed_unverified`` -- distinct from one whose tests actually passed.
COMPLETED_VERIFIED = "completed_verified"
COMPLETED_WITH_FAILURES = "completed_with_failures"
COMPLETED_UNVERIFIED = "completed_unverified"
BLOCKED = "blocked"
OUTCOME_FAILED = "failed"
OUTCOME_CANCELLED = "cancelled"

FINAL_OUTCOMES: frozenset[str] = frozenset(
    {
        COMPLETED_VERIFIED,
        COMPLETED_WITH_FAILURES,
        COMPLETED_UNVERIFIED,
        BLOCKED,
        OUTCOME_FAILED,
        OUTCOME_CANCELLED,
    }
)


def completion_outcome(*, verified: bool, had_failures: bool) -> str:
    """Map verification evidence onto the final outcome vocabulary."""
    if had_failures:
        return COMPLETED_WITH_FAILURES
    if verified:
        return COMPLETED_VERIFIED
    return COMPLETED_UNVERIFIED
