#!/usr/bin/env python3
"""Derive the dark-theme Enkstein mark from the canonical light artwork.

The canonical icon is a red/orange octopus on a white rounded-square tile. On a
dark console that tile reads as a bright white box, so dark mode needs the
inverse treatment: a white octopus on a dark rounded-square tile, with the same
rounded geometry and the same fully transparent pixels outside the corners.

Deriving it here rather than hand-editing a second PNG keeps the two marks in
exact geometric agreement: the silhouette, corner radius, and alpha edge all
come from the same source pixels.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image, ImageChops

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "frontend" / "public" / "enkstein-icon.png"
TARGET = ROOT / "frontend" / "public" / "enkstein-icon-dark.png"

# Matches --rc-bg-surface in the dark console theme, so the tile reads as part
# of the sidebar rather than a pasted-on swatch.
TILE_RGB = (17, 20, 26)
MARK_RGB = (255, 255, 255)


def mark_alpha(source: Image.Image) -> Image.Image:
    """Alpha for the octopus itself, separated from the white tile.

    The tile is pure white and the mark is saturated, so distance from white is
    a clean separator. Using the darkest channel keeps antialiased edge pixels
    proportional instead of hard-thresholding them into a jagged outline.
    """
    red, green, blue = source.split()[:3]
    darkest = ImageChops.darker(ImageChops.darker(red, green), blue)
    # Invert: white tile (255) becomes 0, saturated mark becomes ~255.
    return ImageChops.invert(darkest)


def build(source_path: Path = SOURCE, target_path: Path = TARGET) -> Path:
    source = Image.open(source_path).convert("RGBA")
    tile_alpha = source.getchannel("A")

    dark = Image.new("RGBA", source.size, (*TILE_RGB, 255))
    mark = Image.new("RGBA", source.size, (*MARK_RGB, 255))
    # The mark is painted over the dark tile, then the whole tile is clipped by
    # the source alpha so the rounded corners stay transparent.
    dark.paste(mark, (0, 0), mark_alpha(source))
    dark.putalpha(ImageChops.darker(dark.getchannel("A"), tile_alpha))

    target_path.parent.mkdir(parents=True, exist_ok=True)
    dark.save(target_path, format="PNG")
    return target_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--target", type=Path, default=TARGET)
    arguments = parser.parse_args()
    print(build(arguments.source, arguments.target))


if __name__ == "__main__":
    main()
