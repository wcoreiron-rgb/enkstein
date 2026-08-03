"""Source-level contracts for the sidebar's three-mode navigation.

The blade switches between Chat, Cowork, and Security from a single control,
and Security's Arms start collapsed so the blade stays scannable. These pin
the structural decisions that regress silently; the Playwright specs cover
interactive behaviour.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SIDEBAR = (ROOT / "frontend" / "src" / "components" / "Sidebar.tsx").read_text(encoding="utf-8")

TOP_LEVEL = ("chat", "cowork", "security")


def test_workspace_switch_offers_exactly_three_modes():
    start = SIDEBAR.index("const WORKSPACE_MODES")
    block = SIDEBAR[start:SIDEBAR.index("];", start)]
    for mode in TOP_LEVEL:
        assert f"id: '{mode}'" in block, f"missing workspace mode: {mode}"
    assert block.count("id: '") == len(TOP_LEVEL)


def test_security_arms_are_collapsed_by_default():
    """The blade opens as a short list of Arm headers, not every module."""
    start = SIDEBAR.index("const NAV_GROUPS")
    groups = SIDEBAR[start:SIDEBAR.index("\n];", start)]
    assert "defaultOpen: true" not in groups


def test_group_disclosure_state_persists_and_follows_the_route():
    """A remembered choice survives relaunch; the active group always opens."""
    assert "GROUP_OPEN_STORAGE_PREFIX" in SIDEBAR
    assert "if (hasActive) setOpen(true);" in SIDEBAR


def test_brain_connections_is_reachable_from_chat_and_cowork():
    assert "/marcellus/brains" in SIDEBAR


def test_dark_theme_uses_the_inverted_mark():
    assert "theme === 'dark' ? '/enkstein-icon-dark.png' : '/enkstein-icon.png'" in SIDEBAR
