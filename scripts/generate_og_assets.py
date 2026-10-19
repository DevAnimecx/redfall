"""Generate one 1200x630 social card per public page.

    python scripts/generate_og_assets.py

The cards are real PNGs committed under `site/public/og/`. The generator reads
the same Markdown frontmatter the docs builder reads, so a page cannot ship with
a generic social image. The shield geometry comes from
`scripts/generate_brand_assets.py`, which is also checked against the SVG.

No text is fetched from the network and no page title is invented: the title is
the H1 from the page source.
"""

from __future__ import annotations

import re
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

from generate_brand_assets import _font, mark_image

ROOT = Path(__file__).resolve().parent.parent
CONTENT = ROOT / "site" / "content"
OUT = ROOT / "site" / "public" / "og"
WIDTH, HEIGHT = 1200, 630

BG = "#050505"
INK = "#f5f5f5"
MUTED = "#8a8a8a"
FAINT = "#4c4c4c"
RED = "#ff0033"


def parse_frontmatter(text: str) -> dict[str, str]:
    match = re.match(r"^---\r?\n([\s\S]*?)\r?\n---", text)
    if not match:
        raise SystemExit("content file has no frontmatter")
    meta: dict[str, str] = {}
    for line in match.group(1).splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        value = value.strip()
        if (value.startswith('"') and value.endswith('"')) or (
            value.startswith("'") and value.endswith("'")
        ):
            value = value[1:-1]
        meta[key.strip()] = value
    return meta


def wrap(draw: ImageDraw.ImageDraw, text: str, font, max_width: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if draw.textlength(candidate, font=font) <= max_width:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines


def card(title: str, label: str) -> Image.Image:
    image = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(image)

    # A restrained technical grid, then a soft red glow. Both are generated,
    # not part of a stock template.
    for x in range(0, WIDTH, 80):
        draw.line([(x, 0), (x, HEIGHT)], fill="#0d0d0d", width=1)
    for y in range(0, HEIGHT, 80):
        draw.line([(0, y), (WIDTH, y)], fill="#0d0d0d", width=1)

    glow = Image.new("RGBA", (WIDTH, HEIGHT), (0, 0, 0, 0))
    gdraw = ImageDraw.Draw(glow)
    gdraw.ellipse((760, -250, 1500, 490), fill=(255, 0, 51, 46))
    glow = glow.filter(ImageFilter.GaussianBlur(120))
    image = Image.alpha_composite(image.convert("RGBA"), glow).convert("RGB")
    draw = ImageDraw.Draw(image)

    draw.line([(0, 0), (WIDTH, 0)], fill=RED, width=5)

    mark = mark_image((HEIGHT, HEIGHT), 0.58, (64, 62))
    image.paste(mark, (0, 0), mark)

    title_font = _font(bold=True, size=54)
    wordmark_font = _font(bold=True, size=54)
    label_font = _font(bold=True, size=19)
    footer_font = _font(bold=False, size=21)

    word_x = 238
    draw.text((word_x, 74), "Red", font=wordmark_font, fill=RED)
    word_x += draw.textlength("Red", font=wordmark_font)
    draw.text((word_x, 74), "Fall", font=wordmark_font, fill=INK)

    draw.text((66, 246), label.upper(), font=label_font, fill=RED)

    title_size = 62
    lines: list[str] = []
    while title_size >= 38:
        title_font = _font(bold=True, size=title_size)
        lines = wrap(draw, title, title_font, 1060)
        if len(lines) <= 3:
            break
        title_size -= 4
    line_height = int(title_size * 1.2)
    y = 292
    for line in lines:
        draw.text((66, y), line, font=title_font, fill=INK)
        y += line_height

    draw.text((66, HEIGHT - 50), "devanimecx.github.io/redfall", font=footer_font, fill=FAINT)
    footer = "Every finding executed. Only proofs reported."
    draw.text((WIDTH - 66, HEIGHT - 50), footer, font=footer_font, fill=MUTED, anchor="ra")
    return image


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    pages = []
    for path in sorted(CONTENT.rglob("*.md")):
        meta = parse_frontmatter(path.read_text(encoding="utf-8"))
        title = meta.get("title", "").strip()
        if not title:
            raise SystemExit(f"{path}: missing title")
        group = meta.get("group", "Documentation").strip()
        pages.append((path.stem, title, group))

    cards = [("landing", "Prove the vulnerability. Then prove the fix.", "Execution-verified")]
    cards.extend((page_id, title, group) for page_id, title, group in pages)

    for page_id, title, label in cards:
        target = OUT / f"{page_id}.png"
        card(title, label).save(target, "PNG", optimize=True)
        print(f"wrote {target.relative_to(ROOT)} ({target.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
