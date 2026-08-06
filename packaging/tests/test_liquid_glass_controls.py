"""Liquid Glass must not repaint interactive controls.

A button is also a rounded, bordered box. The glass panel rules matched on
that shape, so with `!important` they overwrote every control's background and
border with the neutral panel surface -- erasing the colour that distinguishes
Approve from Block, and the selected filter from the rest. These checks pin
the exclusion and the light-surface colour mapping.
"""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CSS = ROOT / "frontend" / "src" / "app" / "globals.css"

EXCLUDED_ROLES = (
    ":not(button)",
    ":not(a)",
    ":not([role='button'])",
    ":not([role='tab'])",
)


@pytest.fixture(scope="module")
def css() -> str:
    return CSS.read_text(encoding="utf-8")


def _rule_body(css: str, needle: str) -> str:
    index = css.index(needle)
    return css[index : css.index("}", index)]


def test_panel_surface_rule_excludes_controls(css: str) -> None:
    selector = _rule_body(css, "html.liquid :is(.rounded-xl")
    for role in EXCLUDED_ROLES:
        assert role in selector, f"panel rule repaints {role}"


def test_border_normalisation_excludes_controls(css: str) -> None:
    selector = _rule_body(css, "html.liquid :is(.border,")
    for role in EXCLUDED_ROLES:
        assert role in selector, f"border rule flattens {role}"


def test_no_unscoped_glass_rule_repaints_every_bordered_box(css: str) -> None:
    # The original selectors carried no exclusion at all. If either returns,
    # every control silently loses its state colour again.
    assert "html.liquid .rounded-xl.border,\n" not in css
    assert "html.liquid .border,\nhtml.liquid .border-t," not in css


@pytest.mark.parametrize(
    "utility",
    [
        ".bg-green-900\\/20",
        ".bg-red-900\\/20",
        ".bg-orange-900\\/20",
        ".text-green-400",
        ".text-red-400",
        ".text-orange-400",
    ],
)
def test_dark_console_state_colours_are_remapped_for_light_glass(css: str, utility: str) -> None:
    # These utilities assume a dark background. Left alone they are unreadable
    # on a light translucent panel.
    assert f"html.liquid {utility}" in css, f"{utility} has no Liquid Glass mapping"


def test_controls_still_receive_a_glass_treatment(css: str) -> None:
    # Excluding controls from the panel rule must not leave them flat; they
    # get their own blur so the theme still reads as glass.
    body = _rule_body(css, "html.liquid button,")
    assert "backdrop-filter" in body


def test_overlay_panels_are_opaque(css: str) -> None:
    """A modal floats over page content, not over the desktop.

    The panel surface alpha that makes a card feel like glass makes an overlay
    unreadable: headings and buttons from the page below show straight through
    it. Even 6% transparency was visible in the drawer's empty regions.
    """
    body = _rule_body(css, "html.liquid .fixed.inset-0:is(.z-40, .z-50, [class*='z-[']) > *")
    assert "rgb(252, 253, 254) !important" in body, "overlay panel is not fully opaque"
    assert "rgba" not in body.split("background:")[1].split(";")[0]


def test_overlay_rule_covers_every_z_layer(css: str) -> None:
    # Overlays in the app use z-40, z-50, and arbitrary z-[100]/z-[120].
    # Matching only one leaves the rest transparent.
    for layer in (".z-40", ".z-50", "[class*='z-[']"):
        assert layer in _rule_body(css, "html.liquid .fixed.inset-0:is(")


def test_edge_pinned_drawers_are_covered(css: str) -> None:
    # Some drawers are a sibling of their scrim rather than a child, so they
    # are edge-pinned instead of inset-0.
    assert "html.liquid .fixed.top-0.right-0.h-full" in css


def test_scrim_blurs_the_page_behind_the_overlay(css: str) -> None:
    body = _rule_body(css, "html.liquid .fixed.inset-0:is(.z-40, .z-50, [class*='z-[']) {")
    assert "backdrop-filter" in body


def test_overlay_reads_as_floating_not_embedded(css: str) -> None:
    """An opaque panel in a translucent theme needs explicit depth cues.

    Every other surface in Liquid Glass is see-through, so a hard white
    rectangle with a faint hairline border reads as a card embedded in the page
    rather than a sheet above it. The scrim therefore darkens harder than the
    shared `bg-black/40`, and the panel carries a defined edge plus a deeper
    drop shadow than the light/dark themes need.
    """
    scrim = _rule_body(css, "html.liquid .fixed.inset-0:is(.z-40, .z-50, [class*='z-[']) {")
    assert "rgba(15, 23, 42, .58) !important" in scrim, "scrim does not override bg-black/40"

    for selector in (
        "html.liquid .fixed.inset-0:is(.z-40, .z-50, [class*='z-[']) > *",
        "html.liquid .fixed.top-0.right-0.h-full",
    ):
        body = _rule_body(css, selector)
        assert "rgba(100, 116, 139, .55) !important" in body, f"{selector} edge is too faint"
        assert "0 32px 80px rgba(15, 23, 42, .38)" in body, f"{selector} shadow is too shallow"

def test_nested_panels_contrast_against_the_overlay_surface(css: str) -> None:
    # A card inside an opaque dialog needs contrast against it, not
    # transparency of its own.
    body = _rule_body(
        css,
        "html.liquid .fixed.inset-0:is(.z-40, .z-50, [class*='z-[']) :is(.rounded-xl",
    )
    assert "rgba(241, 245, 249" in body
    assert "backdrop-filter: none" in body


def test_glass_never_hand_writes_the_webkit_backdrop_prefix() -> None:
    """Authoring both forms makes the build drop the standard property and
    emit only the -webkit- alias. Chromium does not support that alias, so a
    hand-prefixed rule silently disables Liquid Glass blur in WebView2 on
    Windows while still looking correct in the packaged macOS WKWebView.
    Autoprefixer produces both forms from the standard declaration alone."""
    css = (
        Path(__file__).resolve().parents[2]
        / "frontend" / "src" / "app" / "globals.css"
    ).read_text(encoding="utf-8")
    offenders = [
        line.strip()
        for line in css.splitlines()
        if line.strip().startswith("-webkit-backdrop-filter:")
    ]
    assert not offenders, (
        "remove the hand-written prefix; autoprefixer emits it: " + "; ".join(offenders)
    )
