"""The dark-theme mark must be a white octopus on a dark rounded tile.

The canonical light artwork sits on a white tile, which reads as a bright box
in the dark console. These checks pin the inverse treatment and, importantly,
the shared rounded geometry: both marks must keep fully transparent corners.
"""

from pathlib import Path

import pytest
from PIL import Image

ROOT = Path(__file__).resolve().parents[2]
LIGHT = ROOT / "frontend" / "public" / "enkstein-icon.png"
DARK = ROOT / "frontend" / "public" / "enkstein-icon-dark.png"


@pytest.fixture(scope="module")
def marks() -> tuple[Image.Image, Image.Image]:
    return (
        Image.open(LIGHT).convert("RGBA"),
        Image.open(DARK).convert("RGBA"),
    )


def test_dark_mark_exists_and_matches_light_geometry(marks):
    light, dark = marks
    assert dark.size == light.size


@pytest.mark.parametrize("corner", [(0, 0), (1023, 0), (0, 1023), (1023, 1023)])
def test_dark_mark_keeps_transparent_rounded_corners(marks, corner):
    _, dark = marks
    assert dark.getpixel(corner)[3] == 0, "outer corners must stay transparent"


def test_dark_mark_uses_a_dark_tile_not_a_white_plate(marks):
    _, dark = marks
    # Sampled inside the tile but outside the octopus silhouette.
    for point in ((512, 40), (300, 300), (724, 300)):
        red, green, blue, alpha = dark.getpixel(point)
        assert alpha == 255, "the tile itself must be opaque"
        assert max(red, green, blue) < 60, f"tile at {point} should be dark, got {(red, green, blue)}"


def test_dark_mark_octopus_is_white(marks):
    _, dark = marks
    for point in ((512, 512), (512, 120)):
        red, green, blue, _ = dark.getpixel(point)
        assert min(red, green, blue) > 200, f"mark at {point} should be white, got {(red, green, blue)}"


def test_light_mark_is_unchanged_red_orange_on_white(marks):
    light, _ = marks
    assert light.getpixel((512, 40))[:3] == (255, 255, 255), "light tile stays white"
    red, green, blue, _ = light.getpixel((512, 512))
    assert red > 200 and green < 120, "light mark stays red/orange"


def test_sidebar_selects_the_dark_mark_only_in_dark_theme():
    sidebar = (ROOT / "frontend" / "src" / "components" / "Sidebar.tsx").read_text(encoding="utf-8")
    assert "theme === 'dark' ? '/enkstein-icon-dark.png' : '/enkstein-icon.png'" in sidebar
    # The glass tile is a presentation asset and must never be product branding.
    assert "favicon-liquid.png" not in sidebar


def test_favicon_offers_a_dark_variant_for_dark_browser_chrome():
    layout = (ROOT / "frontend" / "src" / "app" / "layout.tsx").read_text(encoding="utf-8")
    assert "/enkstein-icon-dark.png" in layout
    assert "prefers-color-scheme: dark" in layout
    assert "favicon-liquid.png" not in layout


def test_dark_mark_is_generated_from_the_canonical_source():
    generator = (ROOT / "scripts" / "generate_dark_app_icon.py").read_text(encoding="utf-8")
    assert "enkstein-icon.png" in generator
    assert "enkstein-icon-dark.png" in generator
    assert "favicon-liquid.png" not in generator
