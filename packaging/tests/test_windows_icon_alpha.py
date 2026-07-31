"""Validate the shipped Windows ICO frame by frame.

Windows loads a different frame per surface, so probing only the first frame
hides the regression that matters: a flattened white plate at 16px or 24px
renders as a white box on a dark desktop even when the 256px frame is fine.
"""

import importlib.util
from pathlib import Path

import pytest
from PIL import IcoImagePlugin

ROOT = Path(__file__).resolve().parents[2]
ICON = ROOT / "packaging" / "windows" / "Enkstein.ico"

EXPECTED_SIZES = {16, 24, 32, 48, 64, 128, 256}

# Mirrors scripts/generate_app_icon.py; used to sample just inside the tile.
CORNER_RADIUS_RATIO = 0.1914


def load_frames():
    with ICON.open("rb") as handle:
        ico = IcoImagePlugin.IcoFile(handle)
        return {size[0]: ico.getimage(size).convert("RGBA") for size in ico.sizes()}


FRAMES = load_frames()


def test_icon_ships_every_required_size():
    assert set(FRAMES) == EXPECTED_SIZES


@pytest.mark.parametrize("size", sorted(EXPECTED_SIZES))
def test_frame_is_32_bit_rgba(size: int):
    frame = FRAMES[size]
    assert frame.mode == "RGBA"
    assert len(frame.getbands()) == 4


@pytest.mark.parametrize("size", sorted(EXPECTED_SIZES))
def test_outer_corners_are_fully_transparent(size: int):
    """Fails the build if the rounded tile came back as an opaque square."""
    frame = FRAMES[size]
    last = size - 1
    corners = {
        "top-left": (0, 0),
        "top-right": (last, 0),
        "bottom-left": (0, last),
        "bottom-right": (last, last),
    }
    opaque = {
        name: frame.getpixel(point)
        for name, point in corners.items()
        if frame.getpixel(point)[3] != 0
    }
    assert not opaque, f"{size}px frame has opaque outer corners: {opaque}"


@pytest.mark.parametrize("size", sorted(EXPECTED_SIZES))
def test_tile_interior_is_opaque_white(size: int):
    """Just inside the rounded corner the white tile must be solid."""
    frame = FRAMES[size]
    inset = max(1, round(size * CORNER_RADIUS_RATIO))
    last = size - 1
    for point in ((inset, inset), (last - inset, inset)):
        red, green, blue, alpha = frame.getpixel(point)
        assert alpha == 255, f"{size}px tile is translucent at {point}"
        assert min(red, green, blue) > 170, f"{size}px tile is not white at {point}"


@pytest.mark.parametrize("size", sorted(EXPECTED_SIZES))
def test_octopus_artwork_is_present(size: int):
    """Guards against shipping a blank tile with the artwork lost in scaling."""
    frame = FRAMES[size]
    opaque = [pixel for pixel in frame.getdata() if pixel[3] == 255]
    assert opaque, f"{size}px frame is fully transparent"
    red = [p for p in opaque if p[0] > 170 and p[1] < 110 and p[2] < 110]
    assert len(red) / len(opaque) > 0.12, f"{size}px frame is missing the octopus"


@pytest.mark.parametrize("size", sorted(EXPECTED_SIZES))
def test_frame_is_not_a_full_opaque_square(size: int):
    frame = FRAMES[size]
    transparent = sum(1 for pixel in frame.getdata() if pixel[3] == 0)
    assert transparent > 0, f"{size}px frame has no transparency at all"


def test_committed_icon_matches_the_canonical_artwork():
    """The committed ICO must match what the generator produces today."""
    spec = importlib.util.spec_from_file_location(
        "generate_app_icon", ROOT / "scripts" / "generate_app_icon.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    source = module.Image.open(module.SOURCE).convert("RGBA")
    for size, frame in FRAMES.items():
        expected = module.render_frame(source, size)
        assert list(frame.getdata()) == list(expected.getdata()), (
            f"{size}px frame is stale; rerun scripts/generate_app_icon.py"
        )
