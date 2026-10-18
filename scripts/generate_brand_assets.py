"""Generate the raster brand assets (social card, touch icons, favicon copy).

    python scripts/generate_brand_assets.py

The SVG mark in `assets/` is the source of truth for the shapes; this script
redraws the same geometry with Pillow because Pillow cannot render SVG. The
shield gradient is composited through a mask, so joins stay clean at every
size. Keep the point lists below in sync with `assets/redfall-mark.svg`.

Outputs (into `site/public/`): `og.png` (1200x630), `apple-touch-icon.png`
(180), `android-chrome-192.png`, `android-chrome-512.png`, `favicon.svg`.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "assets"
SITE_PUBLIC = ROOT / "site" / "public"

# 256-space geometry, identical to assets/redfall-mark.svg
SHIELD = [(46, 26), (210, 26), (234, 50), (234, 142), (128, 236), (22, 142), (22, 50)]
SHIELD_WIDTH = 16.0
CIRCLE = (128, 118, 42)
CIRCLE_WIDTH = 10.0
TICKS = [((128, 52), (128, 68)), ((128, 168), (128, 184)), ((60, 118), (76, 118)), ((180, 118), (196, 118))]
TICK_WIDTH = 10.0
DOT = (128, 118, 12)

RED_TOP = (255, 81, 71)
RED_BOTTOM = (140, 2, 2)
CANVAS_TOP = 10.0
CANVAS_BOTTOM = 250.0


def _lerp(a: tuple[int, int, int], b: tuple[int, int, int], t: float) -> tuple[int, int, int]:
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b))


def _font(bold: bool, size: int) -> ImageFont.FreeTypeFont:
    candidates = ["segoeuib.ttf" if bold else "segoeui.ttf", "arialbd.ttf" if bold else "arial.ttf", "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"]
    for name in candidates:
        for base in (Path(r"C:\Windows\Fonts"), Path("/usr/share/fonts/truetype/dejavu"), Path("/System/Library/Fonts/Supplemental")):
            path = base / name
            if path.is_file():
                return ImageFont.truetype(str(path), size)
    raise SystemExit("no usable TTF font found for the brand assets")


def mark_image(canvas: tuple[int, int], scale: float, offset: tuple[float, float]) -> Image.Image:
    """The mark (shield + crosshair) as an RGBA image on a transparent canvas."""
    width, height = canvas
    ox, oy = offset

    def point(p: tuple[float, float]) -> tuple[float, float]:
        return (ox + p[0] * scale, oy + p[1] * scale)

    mask = Image.new("L", canvas, 0)
    draw = ImageDraw.Draw(mask)
    # The wrap-around segment is drawn twice (SHIELD[0] is revisited) so the
    # closing joint overlaps instead of showing a notch at the chamfer.
    outline = [point(p) for p in SHIELD] + [point(SHIELD[0]), point(SHIELD[1])]
    draw.line(outline, fill=255, width=max(2, round(SHIELD_WIDTH * scale)), joint="curve")
    cx, cy, r = CIRCLE
    draw.ellipse(
        [point((cx - r, cy - r)), point((cx + r, cy + r))],
        outline=255,
        width=max(2, round(CIRCLE_WIDTH * scale)),
    )
    for (x1, y1), (x2, y2) in TICKS:
        draw.line([point((x1, y1)), point((x2, y2))], fill=255, width=max(2, round(TICK_WIDTH * scale)))
    dot_cx, dot_cy, dot_r = DOT
    draw.ellipse([point((dot_cx - dot_r, dot_cy - dot_r)), point((dot_cx + dot_r, dot_cy + dot_r))], fill=255)

    gradient = Image.new("RGBA", canvas)
    pixels = gradient.load()
    span = CANVAS_BOTTOM - CANVAS_TOP
    for y in range(height):
        t = (y / scale - CANVAS_TOP) / span if scale else 0.0
        t = min(1.0, max(0.0, t))
        color = _lerp(RED_TOP, RED_BOTTOM, t) + (255,)
        for x in range(width):
            pixels[x, y] = color

    out = Image.new("RGBA", canvas, (0, 0, 0, 0))
    out.paste(gradient, (0, 0), mask)
    return out


def shield_only(size: int, scale: float) -> Image.Image:
    """Mark centered on a square canvas (transparent background)."""
    canvas = (size, size)
    mark_w = 256 * scale
    offset = ((size - mark_w) / 2, (size - mark_w) / 2)
    return mark_image(canvas, scale, offset)


def rounded_square(size: int, color: str, radius_ratio: float = 0.2) -> Image.Image:
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle([0, 0, size - 1, size - 1], radius=round(size * radius_ratio), fill=color)
    return image


def social_card() -> Image.Image:
    width, height = 1200, 630
    card = Image.new("RGB", (width, height), "#0d1117")
    mark = mark_image((width, height), 1.16, (92, 168))
    card.paste(mark, (0, 0), mark)

    draw = ImageDraw.Draw(card)
    title_font = _font(bold=True, size=122)
    tagline_font = _font(bold=False, size=34)
    url_font = _font(bold=False, size=26)

    x = 458
    y = 250
    red = "Red"
    draw.text((x, y), red, font=title_font, fill="#ff2b2b", anchor="lm")
    x += draw.textlength(red, font=title_font)
    draw.text((x, y), "Fall", font=title_font, fill="#ffffff", anchor="lm")

    draw.text((462, 338), "Autonomous vulnerability discovery", font=tagline_font, fill="#98a2b3", anchor="lm")
    draw.text((462, 382), "and verified repair.", font=tagline_font, fill="#98a2b3", anchor="lm")
    draw.text((width - 72, height - 52), "github.com/DevAnimecx/redfall", font=url_font, fill="#6b7280", anchor="rs")
    return card


def touch_icon(size: int) -> Image.Image:
    icon = rounded_square(size, "#0d1117", 0.22)
    mark = shield_only(size, size * 0.62 / 256)
    return Image.alpha_composite(icon, mark)


def main() -> int:
    SITE_PUBLIC.mkdir(parents=True, exist_ok=True)

    card_path = SITE_PUBLIC / "og.png"
    social_card().save(card_path, "PNG", optimize=True)

    (SITE_PUBLIC / "apple-touch-icon.png").write_bytes(_png_bytes(touch_icon(180)))
    (SITE_PUBLIC / "android-chrome-192.png").write_bytes(_png_bytes(touch_icon(192)))
    (SITE_PUBLIC / "android-chrome-512.png").write_bytes(_png_bytes(touch_icon(512)))

    shutil.copyfile(ASSETS / "redfall-mark.svg", SITE_PUBLIC / "favicon.svg")

    for name in ("og.png", "apple-touch-icon.png", "android-chrome-192.png", "android-chrome-512.png", "favicon.svg"):
        path = SITE_PUBLIC / name
        print(f"wrote {path.relative_to(ROOT)} ({path.stat().st_size:,} bytes)")
    return 0


def _png_bytes(image: Image.Image) -> bytes:
    import io

    buffer = io.BytesIO()
    image.save(buffer, "PNG", optimize=True)
    return buffer.getvalue()


if __name__ == "__main__":
    raise SystemExit(main())
