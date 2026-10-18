"""The brand assets are built artefacts; these tests pin their contracts.

`assets/redfall-mark.svg` is the source of truth for the shield geometry.
`scripts/generate_brand_assets.py` redraws the same shapes with Pillow (it
cannot render SVG), so the two must not drift: the parser below reads the
SVG path and compares it with the script's point list. The raster files
committed under `site/public/` are checked for the exact sizes the page's
metadata promises.
"""

from __future__ import annotations

import importlib.util
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "generate_brand_assets.py"
SVG_NS = "{http://www.w3.org/2000/svg}"


def _load_generator():
    pytest.importorskip("PIL", reason="Pillow is required to regenerate the brand assets")
    spec = importlib.util.spec_from_file_location("generate_brand_assets", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _shield_points(svg_path: Path) -> list[tuple[float, float]]:
    """Absolute points of the first <path> (the shield outline) in the SVG."""
    root = ET.parse(svg_path).getroot()
    path = root.find(f".//{SVG_NS}path")
    assert path is not None, f"no shield path in {svg_path}"
    tokens = re.findall(r"[MHLVZ]|-?\d+(?:\.\d+)?", path.attrib["d"])

    points: list[tuple[float, float]] = []
    x = y = 0.0
    i = 0
    while i < len(tokens):
        command = tokens[i]
        i += 1
        if command == "M" or command == "L":
            x, y = float(tokens[i]), float(tokens[i + 1])
            i += 2
            points.append((x, y))
        elif command == "H":
            x = float(tokens[i])
            i += 1
            points.append((x, y))
        elif command == "V":
            y = float(tokens[i])
            i += 1
            points.append((x, y))
        elif command == "Z":
            break
        else:  # pragma: no cover - the source path only uses absolute MHLVZ
            raise AssertionError(f"unsupported SVG path command {command!r}")
    return points


def _png_size(name: str) -> tuple[int, int]:
    pillow = pytest.importorskip("PIL", reason="Pillow is required to inspect the raster assets")
    from PIL import Image

    with Image.open(ROOT / "site" / "public" / name) as image:
        return image.size


def test_brand_svgs_are_valid_xml() -> None:
    svgs = sorted((ROOT / "assets").glob("*.svg"))
    assert [p.name for p in svgs] == [
        "redfall-logo-dark.svg",
        "redfall-logo-light.svg",
        "redfall-mark.svg",
    ]
    for svg in svgs:
        ET.parse(svg)


def test_mark_geometry_matches_the_raster_generator() -> None:
    generator = _load_generator()
    svg_points = _shield_points(ROOT / "assets" / "redfall-mark.svg")
    assert svg_points == [(float(x), float(y)) for x, y in generator.SHIELD]


def test_committed_raster_assets_have_the_promised_sizes() -> None:
    # og:image advertises 1200x630; the icon links advertise these sizes.
    assert _png_size("og.png") == (1200, 630)
    assert _png_size("apple-touch-icon.png") == (180, 180)
    assert _png_size("android-chrome-192.png") == (192, 192)
    assert _png_size("android-chrome-512.png") == (512, 512)


def test_site_favicon_is_the_repository_mark() -> None:
    assert (ROOT / "site" / "public" / "favicon.svg").read_bytes() == (
        ROOT / "assets" / "redfall-mark.svg"
    ).read_bytes()
