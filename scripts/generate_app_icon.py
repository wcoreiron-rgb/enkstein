#!/usr/bin/env python3
"""Render the Windows application icon from the canonical Enkstein artwork.

The visible artwork is a red/orange octopus centred on a white rounded-square
tile. The ICO canvas stays square, but every pixel outside the rounded tile has
to be fully transparent so the shortcut does not read as a white box on a dark
desktop.

Generating the ICO here rather than during the Windows build keeps the shipped
frames deterministic, removes the ImageMagick build dependency, and lets the
packaging tests inspect the exact bytes that Windows will load.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "frontend" / "public" / "enkstein-icon.png"
TARGET = ROOT / "packaging" / "windows" / "Enkstein.ico"

# Windows picks a frame per surface: 16/24 for the taskbar and small shell
# views, 32/48 for the Desktop, 256 for large icon views and the installer.
SIZES = (16, 24, 32, 48, 64, 128, 256)

# Matches the corner radius already baked into the 1024px source artwork.
CORNER_RADIUS_RATIO = 0.1914

# Supersampling the mask keeps the rounded edge smooth at 16px, where a mask
# drawn directly at target size would stair-step badly.
MASK_SUPERSAMPLE = 8


def rounded_tile_mask(size: int) -> Image.Image:
    """An antialiased alpha mask for the rounded tile at ``size`` pixels."""
    scale = size * MASK_SUPERSAMPLE
    mask = Image.new("L", (scale, scale), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        (0, 0, scale - 1, scale - 1),
        radius=int(round(scale * CORNER_RADIUS_RATIO)),
        fill=255,
    )
    # BOX is an area average: unlike LANCZOS it cannot overshoot, so a fully
    # transparent supersampled corner stays exactly 0 after the downscale.
    return mask.resize((size, size), Image.BOX)


def render_frame(source: Image.Image, size: int) -> Image.Image:
    """Downscale the artwork and clamp it to the rounded tile.

    Resampling alone leaves a few units of ringing alpha in the corners, which
    is enough to fail a strict transparency check, so the mask is applied as a
    hard upper bound on the alpha channel.
    """
    frame = source.resize((size, size), Image.LANCZOS)
    frame.putalpha(ImageChops.darker(frame.getchannel("A"), rounded_tile_mask(size)))
    return frame


def build(source_path: Path = SOURCE, target_path: Path = TARGET) -> Path:
    source = Image.open(source_path).convert("RGBA")
    frames = [render_frame(source, size) for size in SIZES]
    target_path.parent.mkdir(parents=True, exist_ok=True)
    # Pillow writes the base image plus the appended frames; passing the largest
    # first keeps the 256px frame authoritative for shells that read frame 0.
    frames[-1].save(
        target_path,
        format="ICO",
        sizes=[(size, size) for size in SIZES],
        append_images=frames[:-1],
    )
    return target_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--target", type=Path, default=TARGET)
    args = parser.parse_args()
    written = build(args.source, args.target)
    print(f"Wrote {written} ({', '.join(f'{s}x{s}' for s in SIZES)})")


if __name__ == "__main__":
    main()
