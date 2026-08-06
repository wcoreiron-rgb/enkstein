"""Guards the execution orb indicators.

The orb is an animated state indicator, not decoration. Two properties matter
enough to pin: it must depict a stage the runtime genuinely reported, and it
must respect a reduced-motion preference rather than animating forever.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ORB = ROOT / "frontend" / "src" / "components" / "ExecutionOrb.tsx"
WORKSPACE = ROOT / "frontend" / "src" / "app" / "marcellus" / "ai-workspace.tsx"
PACKAGE_JSON = ROOT / "frontend" / "package.json"
PREFERENCE = ROOT / "frontend" / "src" / "lib" / "activity-indicator.ts"
AUTH_BOUNDARY = ROOT / "frontend" / "src" / "components" / "AuthBoundary.tsx"
BRAINS_PAGE = ROOT / "frontend" / "src" / "app" / "marcellus" / "brains" / "page.tsx"
MAC_APP = ROOT / "packaging" / "macos" / "MarcellusApp.swift"
BUILD_SCRIPT = ROOT / "scripts" / "build_macos_pkg.sh"


@pytest.fixture(scope="module")
def orb() -> str:
    return ORB.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def workspace() -> str:
    return WORKSPACE.read_text(encoding="utf-8")


def test_orb_dependency_is_pinned_exactly() -> None:
    """A floating range on a days-old package would pull unreviewed code into
    a security product on the next install."""
    manifest = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))
    version = manifest["dependencies"]["thinking-orbs"]
    assert re.fullmatch(r"\d+\.\d+\.\d+", version), f"not an exact pin: {version}"


def test_orb_is_client_only(orb: str) -> None:
    """The orb paints to a canvas and reads the theme from the DOM, so a
    server render produces a blank element that flashes on hydration."""
    assert "ssr: false" in orb


def test_orb_honours_reduced_motion(orb: str) -> None:
    assert "prefers-reduced-motion" in orb
    assert "paused={paused || reducedMotion}" in orb, (
        "reduced motion must freeze the orb rather than being ignored"
    )


def test_every_activity_maps_to_an_orb_state(orb: str) -> None:
    """A missing entry would render undefined and crash the timeline."""
    union = re.search(r"export type ExecutionActivity =(.+?);", orb, re.S)
    assert union, "ExecutionActivity union is no longer declared as expected"
    activities = set(re.findall(r"'([a-z-]+)'", union.group(1)))
    assert activities, "no activities parsed"

    mapping = re.search(r"ACTIVITY_ORB: Record<ExecutionActivity, OrbState> = \{(.+?)\n\};", orb, re.S)
    assert mapping, "ACTIVITY_ORB is no longer declared as expected"
    mapped = set(re.findall(r"^\s*'?([a-z-]+)'?:", mapping.group(1), re.M))

    labels = re.search(r"ACTIVITY_LABEL: Record<ExecutionActivity, string> = \{(.+?)\n\};", orb, re.S)
    assert labels, "ACTIVITY_LABEL is no longer declared as expected"
    labelled = set(re.findall(r"^\s*'?([a-z-]+)'?:", labels.group(1), re.M))

    assert activities <= mapped, f"unmapped activities: {activities - mapped}"
    assert activities <= labelled, f"unlabelled activities: {activities - labelled}"


def test_orb_reflects_reported_state_not_decoration(workspace: str) -> None:
    """The stage is derived from the step the runtime reported. If the orb were
    hardcoded at every call site it would be decoration wearing a state's
    clothes."""
    assert "function stepActivity(step: ExecutionStep)" in workspace
    assert "activity={stepActivity(" in workspace


def test_orb_only_marks_genuinely_active_steps(workspace: str) -> None:
    """A done or skipped step must keep its terminal icon; an orb there would
    imply work still in flight."""
    block = workspace[workspace.index("function ExecutionTimeline"):]
    block = block[: block.index("\n}\n")]
    done_index = block.index("step.status === 'done'")
    orb_index = block.index("<ExecutionOrb")
    assert done_index < orb_index, "the orb is rendered before the terminal states are handled"
    assert "spinning ? (" in block, "the orb is not gated on the step being active"


def test_waiting_and_streaming_are_distinguished(workspace: str) -> None:
    """The whole point of the browser-session work was that 'submitted but
    silent' and 'actually streaming' are different states."""
    body = workspace[workspace.index("function stepActivity"):]
    body = body[: body.index("\n}\n")]
    assert "'streaming'" in body
    assert "'waiting-on-brain'" in body


def test_indicator_preference_defaults_to_orb_and_offers_spinner() -> None:
    source = PREFERENCE.read_text(encoding="utf-8")
    assert "'orb' | 'spinner'" in source
    assert "return 'orb';" in source, "the orb must be the default"
    assert "localStorage" in source, "the choice must survive a reload"


def test_spinner_choice_restores_the_original_indicator(workspace: str) -> None:
    """Turning orbs off must bring back the rotating glyph, not simply remove
    the indicator and leave a running turn looking idle."""
    block = workspace[workspace.index("function ExecutionTimeline"):]
    block = block[: block.index("\n}\n")]
    assert "indicator === 'orb' ? (" in block
    spinner_branch = block[block.index("indicator === 'orb' ? ("):]
    assert "animate-spin" in spinner_branch[:600], (
        "the spinner branch does not animate, so a running step looks stalled"
    )


def test_indicator_toggle_is_reachable_and_labelled(workspace: str) -> None:
    """A preference with no control is not a preference."""
    block = workspace[workspace.index("function ExecutionTimeline"):]
    block = block[: block.index("\n}\n")]
    assert "onToggleIndicator" in block
    assert "aria-label=" in block[block.index("onClick={onToggleIndicator}"):][:400]


def test_indicator_is_read_after_mount(workspace: str) -> None:
    """Reading localStorage during render would hydrate to a different
    indicator than the server produced."""
    assert "useEffect(() => setActivityIndicator(readStoredActivityIndicator()), [])" in workspace


def test_web_launch_screen_uses_the_orb() -> None:
    source = AUTH_BOUNDARY.read_text(encoding="utf-8")
    assert "<ExecutionOrb" in source, "the launch screen still uses the bare spinner"
    assert 'size={64}' in source, "the launch orb should use the large preset"
    # The launch screen paints a fixed white surface regardless of the saved
    # theme, so auto-detection would resolve a theme this screen is not using.
    assert 'theme="light"' in source


def test_launch_orb_sizes_match_across_the_handoff() -> None:
    """The native splash shows first and swaps to web content mid-startup. A
    size mismatch would make the indicator visibly jump at the handoff."""
    web = AUTH_BOUNDARY.read_text(encoding="utf-8")
    native = MAC_APP.read_text(encoding="utf-8")

    web_scale = re.search(r"scale=\{(\d+)\}", web)
    assert web_scale, "the launch orb no longer sets an explicit rendered size"

    native_size = re.search(
        r"intrinsicContentSize: NSSize \{ NSSize\(width: (\d+), height: (\d+)\)", native
    )
    assert native_size, "the native launch orb no longer declares its size"
    assert native_size.group(1) == native_size.group(2), "the native orb is not square"
    assert web_scale.group(1) == native_size.group(1), (
        f"web launch orb is {web_scale.group(1)}px but native is {native_size.group(1)}px"
    )


def _swift_code_only(source: str) -> str:
    """Drops `///` and `//` comments so an assertion cannot be satisfied -- or
    broken -- by explanatory prose that merely mentions a symbol."""
    return "\n".join(
        line for line in source.splitlines() if not line.strip().startswith("//")
    )


def test_native_splash_uses_the_orb() -> None:
    """The AppKit splash is shown first and holds through the whole Docker
    wait, so leaving a stock spinner there means the longest part of startup
    is the one surface that did not get the new indicator."""
    source = _swift_code_only(MAC_APP.read_text(encoding="utf-8"))
    assert "final class LaunchOrbView" in source
    assert "spinner = LaunchOrbView()" in source
    assert "NSProgressIndicator" not in source, "the native splash still uses the stock spinner"


def test_native_orb_matches_progress_indicator_interface() -> None:
    """Several startup paths -- terminal failure, retry, handoff to web --
    drive the indicator through NSProgressIndicator's interface."""
    source = MAC_APP.read_text(encoding="utf-8")
    assert "func startAnimation(_ sender: Any?)" in source
    assert "func stopAnimation(_ sender: Any?)" in source


def test_native_orb_honours_reduced_motion_and_transparency() -> None:
    source = MAC_APP.read_text(encoding="utf-8")
    assert "accessibilityDisplayShouldReduceMotion" in source
    assert "override var isOpaque: Bool { false }" in source, (
        "an opaque launch orb would show as a plate on a vibrant splash"
    )


def test_macos_build_links_corevideo() -> None:
    """The native orb drives its frames from a CVDisplayLink."""
    script = BUILD_SCRIPT.read_text(encoding="utf-8")
    assert script.count("-framework CoreVideo") >= 2, "both architectures must link CoreVideo"


def test_brains_tile_uses_the_constellation_orb() -> None:
    """Brain Connections is about the network itself, not a turn in flight,
    so its orb depicts wiring rather than borrowing a work-in-progress stage."""
    source = BRAINS_PAGE.read_text(encoding="utf-8")
    assert 'activity="consensus"' in source, (
        "the Brains tile orb must use the constellation state"
    )


def test_brains_orb_is_hidden_when_nothing_is_connected() -> None:
    """A live constellation above a zero count would claim connections that
    do not exist -- the one case this indicator could misrepresent."""
    source = BRAINS_PAGE.read_text(encoding="utf-8")
    assert re.search(
        r"readyCount\s*>\s*0\s*&&\s*\(?\s*<ExecutionOrb", source
    ), "the Brains tile orb must be gated on a non-zero ready count"


def test_brains_zero_state_explains_itself() -> None:
    """Ready Brains keeps the height of the stacked column beside it, so
    dropping the orb without replacing it leaves a void that reads as a load
    which never finished."""
    source = BRAINS_PAGE.read_text(encoding="utf-8")
    assert "readyCount === 0 &&" in source, (
        "the zero state must render guidance where the constellation would be"
    )


def test_brains_stat_grid_stacks_before_the_orb_overflows() -> None:
    """At the `sm` breakpoint the two columns are narrow enough that the
    constellation spills past its card, so the split has to wait for `md`."""
    source = BRAINS_PAGE.read_text(encoding="utf-8")
    assert "md:grid-cols-2" in source
    assert "sm:grid-cols-2" not in source, (
        "splitting at sm overflows the constellation on narrow viewports"
    )
