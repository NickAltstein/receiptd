"""Pillow-based visual card renderer: card.png (1200x630 & 1080x1080) + card.svg.

Pure Pillow - no browser, no Playwright, no HTML. Both 1200x630 (social) and
1080x1080 (square) are rendered from the same layout template.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Iterable

from PIL import Image, ImageDraw, ImageFont

from receiptd.card.models import CATEGORIES, Report

WIDTH, HEIGHT = 1200, 630
SOCIAL_SIZE = (1200, 630)
SQUARE_SIZE = (1080, 1080)
SUPPORTED_SIZES = (SOCIAL_SIZE, SQUARE_SIZE)

DEFAULT_LOGO_PATH = Path(__file__).resolve().parent / "assets" / "logo.png"
REPO_URL = "github.com/NickAltstein/receiptd"
SUBTITLE_TEXT = "Signed summary of a session's tool-use profile"
FOOTER_SUMMARY = "Generated locally · Ed25519-signed · offline hash-chain checking"

# Dark theme palette.
BG = (13, 17, 23)
PANEL = (22, 27, 34)
PANEL_ALT = (28, 33, 41)
BORDER = (48, 54, 61)
FG = (230, 237, 243)
DIM = (139, 148, 158)
RED = (248, 81, 73)
RED_BG = (45, 22, 26)
RED_BORDER = (160, 48, 45)
NEUTRAL_BG = (22, 27, 34)
ACCENT = (88, 166, 255)

FONTS = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
    "/usr/share/fonts/truetype/freefont/FreeSansBold.ttf",
    "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
    "/System/Library/Fonts/Helvetica.ttc",
]
REGULAR_FONTS = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    "/usr/share/fonts/truetype/freefont/FreeSans.ttf",
    "/System/Library/Fonts/Supplemental/Arial.ttf",
    "/System/Library/Fonts/Helvetica.ttc",
]
MONO_FONTS = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationMono-Bold.ttf",
    "/System/Library/Fonts/Menlo.ttc",
    "/System/Library/Fonts/SFNSMono.ttf",
]

CATEGORY_LABELS = {
    "PRIVATE": "Private data",
    "UNTRUSTED": "Untrusted input",
    "EGRESS": "Egress",
}


def _load_font(candidates: Iterable[str], size: int):
    for path in candidates:
        if Path(path).exists():
            try:
                return ImageFont.truetype(path, size)
            except OSError:
                continue
    try:
        return ImageFont.load_default(size=size)
    except TypeError:
        return ImageFont.load_default()


def font_bold(size: int):
    return _load_font(FONTS, size)


def font_regular(size: int):
    return _load_font(REGULAR_FONTS, size)


def font_mono(size: int):
    return _load_font(MONO_FONTS, size)


def _short_hash(report: Report) -> str:
    """First 12 hex chars of SHA-256 over canonical evidence fields."""
    material = "|".join(
        f"{h.category},{h.index},{h.tool},{h.target},{h.rule}" for h in report.hits
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]


def _parse_iso_dt(raw: str | None) -> datetime | None:
    if not raw:
        return None
    text = raw.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        try:
            return datetime.strptime(text[:10], "%Y-%m-%d")
        except ValueError:
            return None


def format_date_window(report: Report) -> str:
    """Compute absolute date range from earliest and latest session timestamps.

    Shows an absolute date range ("Nov 3 - Nov 23, 2026"); shows "<1 day" only
    when the span is under 24 hours. Never shows "Last 0 Days".
    """
    dts: list[datetime] = []
    for s in report.sessions:
        for raw in (s.started, s.ended):
            dt = _parse_iso_dt(raw)
            if dt is not None:
                dts.append(dt)
    if not dts:
        for h in report.hits:
            dt = _parse_iso_dt(h.timestamp)
            if dt is not None:
                dts.append(dt)
    if not dts:
        return "Date unavailable"

    # Normalize naive vs aware if mixed.
    aware = [d for d in dts if d.tzinfo is not None]
    if aware and len(aware) != len(dts):
        dts = [d.replace(tzinfo=None) for d in dts]

    earliest = min(dts)
    latest = max(dts)
    span_seconds = (latest - earliest).total_seconds()

    def _fmt_md(d: datetime) -> str:
        return f"{d.strftime('%b')} {d.day}"

    def _fmt_mdy(d: datetime) -> str:
        return f"{d.strftime('%b')} {d.day}, {d.year}"

    if span_seconds < 86400:
        if earliest.date() == latest.date():
            return f"{_fmt_mdy(earliest)} (<1 day)"
        return f"{_fmt_md(earliest)} - {_fmt_mdy(latest)} (<1 day)"

    if earliest.year == latest.year:
        return f"{_fmt_md(earliest)} - {_fmt_mdy(latest)}"
    return f"{_fmt_mdy(earliest)} - {_fmt_mdy(latest)}"


def _total_calls(report: Report) -> int:
    return sum(s.tool_calls for s in report.sessions)


def _trifecta_stats(report: Report) -> tuple[int, int, float]:
    total = len(report.sessions)
    tri = report.trifecta_sessions
    if tri == 0 and total == 1 and all(report.counts.get(c, 0) > 0 for c in CATEGORIES):
        tri = 1
    pct = (tri / total * 100.0) if total > 0 else 0.0
    return tri, total, pct


def _session_vector_count(report: Report, category: str) -> int:
    svc = getattr(report, "session_vector_counts", None) or {}
    val = svc.get(category)
    if val is not None and (val > 0 or len(report.sessions) != 1):
        return int(val)
    if len(report.sessions) == 1 and report.counts.get(category, 0) > 0:
        return 1
    return 0


def _example_for_category(report: Report, category: str) -> str:
    for hit in sorted(
        (h for h in report.hits if h.category == category),
        key=lambda h: h.index,
    ):
        return f"{hit.tool}: {hit.target}"
    return "No hits in audited sessions"


def _truncate_to_width(draw: ImageDraw.ImageDraw, text: str, font, max_width: float) -> str:
    if max_width <= 0:
        return ""
    if draw.textlength(text, font=font) <= max_width:
        return text
    ellipsis = "…"
    lo, hi = 0, len(text)
    best = ellipsis
    while lo <= hi:
        mid = (lo + hi) // 2
        candidate = text[:mid].rstrip() + ellipsis
        if draw.textlength(candidate, font=font) <= max_width:
            best = candidate
            lo = mid + 1
        else:
            hi = mid - 1
    return best


def _hex(rgb: tuple[int, int, int]) -> str:
    return "#{:02x}{:02x}{:02x}".format(*rgb)


def _resolve_logo_path(logo_path: Path | str | None) -> Path:
    path = Path(logo_path) if logo_path is not None else DEFAULT_LOGO_PATH
    if not path.is_file():
        raise FileNotFoundError(f"Logo file not found: {path}")
    return path


def _build_layout_spec(
    report: Report,
    width: int,
    height: int,
    json_name: str,
    draw: ImageDraw.ImageDraw,
) -> dict:
    """Compute unified layout geometry for 1200x630 and 1080x1080."""
    is_square = height >= width
    pad = 48
    inner_w = width - 2 * pad
    tri_count, total_sessions, tri_pct = _trifecta_stats(report)
    is_risk = tri_count > 0

    # Header geometry
    logo_h = 38
    header_y = 40 if not is_square else 48
    title_font = font_bold(36 if not is_square else 42)
    subtitle_font = font_regular(18 if not is_square else 20)
    meta_font = font_mono(15 if not is_square else 17)

    date_str = format_date_window(report)
    calls_str = f"{_total_calls(report):,} calls"
    meta_line = f"{date_str}  ·  {calls_str}"

    # Verdict banner geometry
    verdict_y = header_y + (84 if not is_square else 98)
    verdict_h = 84 if not is_square else 112
    verdict_title_font = font_bold(24 if not is_square else 28)
    verdict_rate_font = font_mono(20 if not is_square else 22)

    verdict_text = f"All three present in {tri_count} of {total_sessions} sessions"
    rate_text = f"{tri_count} of {total_sessions} sessions, {tri_pct:.1f}%"

    # Vector tiles geometry (equal height)
    tiles_y = verdict_y + verdict_h + (24 if not is_square else 32)
    footer_h = 74 if not is_square else 88
    tiles_bottom = height - pad - footer_h
    tiles_h = tiles_bottom - tiles_y

    gap = 18
    tile_w = (inner_w - 2 * gap) // 3
    tile_label_font = font_bold(18 if not is_square else 20)
    tile_num_font = font_mono(48 if not is_square else 64)
    tile_sub_font = font_regular(15 if not is_square else 17)
    tile_ex_font = font_regular(14 if not is_square else 16)

    tiles = []
    for idx, category in enumerate(CATEGORIES):
        x0 = pad + idx * (tile_w + gap)
        x1 = x0 + tile_w
        n_sess = _session_vector_count(report, category)
        ex_raw = _example_for_category(report, category)
        ex_text = _truncate_to_width(draw, ex_raw, tile_ex_font, tile_w - 40)
        tiles.append(
            {
                "category": category,
                "label": CATEGORY_LABELS[category],
                "x0": x0,
                "y0": tiles_y,
                "x1": x1,
                "y1": tiles_y + tiles_h,
                "count_text": str(n_sess),
                "sub_text": f"Seen in {n_sess} of {total_sessions} sessions",
                "example_text": ex_text,
            }
        )

    # Footer geometry (two lines so nothing clips at either width)
    footer_y1 = height - pad - 44
    footer_y2 = height - pad - 18
    footer_font = font_regular(14 if not is_square else 15)
    footer_mono_font = font_mono(13 if not is_square else 14)

    footer_left_top = _truncate_to_width(draw, FOOTER_SUMMARY, footer_font, inner_w)
    verify_cmd = f"receiptd verify-card {json_name}"
    repo_text = REPO_URL
    # Ensure repo_text + verify_cmd never collide or clip
    max_verify_w = inner_w - draw.textlength(repo_text, font=footer_mono_font) - 24
    verify_cmd = _truncate_to_width(draw, verify_cmd, footer_mono_font, max_verify_w)

    return {
        "width": width,
        "height": height,
        "pad": pad,
        "is_risk": is_risk,
        "is_square": is_square,
        "logo_h": logo_h,
        "header_y": header_y,
        "title_font": title_font,
        "subtitle_font": subtitle_font,
        "meta_font": meta_font,
        "meta_line": meta_line,
        "verdict_y": verdict_y,
        "verdict_h": verdict_h,
        "verdict_title_font": verdict_title_font,
        "verdict_rate_font": verdict_rate_font,
        "verdict_text": verdict_text,
        "rate_text": rate_text,
        "tile_label_font": tile_label_font,
        "tile_num_font": tile_num_font,
        "tile_sub_font": tile_sub_font,
        "tile_ex_font": tile_ex_font,
        "tiles": tiles,
        "footer_y1": footer_y1,
        "footer_y2": footer_y2,
        "footer_font": footer_font,
        "footer_mono_font": footer_mono_font,
        "footer_left_top": footer_left_top,
        "repo_text": repo_text,
        "verify_cmd": verify_cmd,
    }


def render_card_png(
    report: Report,
    path,
    *,
    size: tuple[int, int] = SOCIAL_SIZE,
    logo_path: Path | str | None = None,
) -> list[tuple[str, tuple[int, int, int, int]]]:
    """Render card PNG at `size` (1200x630 or 1080x1080) and return drawn text bounds."""
    width, height = size
    resolved_logo = _resolve_logo_path(logo_path)
    image = Image.new("RGB", (width, height), BG)
    draw = ImageDraw.Draw(image)
    json_name = Path(path).with_suffix(".json").name
    spec = _build_layout_spec(report, width, height, json_name, draw)

    bounds: list[tuple[str, tuple[int, int, int, int]]] = []

    def _draw_text(xy: tuple[float, float], text: str, font, fill) -> None:
        bbox = draw.textbbox(xy, text, font=font)
        draw.text(xy, text, font=font, fill=fill)
        bounds.append((text, bbox))

    # Top accent bar: red only for risk, neutral border otherwise.
    top_bar_color = RED if spec["is_risk"] else BORDER
    draw.rectangle([0, 0, width, 6], fill=top_bar_color)

    # Logo (top-left beside title)
    with Image.open(resolved_logo) as raw_logo:
        logo_rgba = raw_logo.convert("RGBA")
        aspect = logo_rgba.width / logo_rgba.height
        logo_w = max(1, round(spec["logo_h"] * aspect))
        resized_logo = logo_rgba.resize((logo_w, spec["logo_h"]), Image.Resampling.LANCZOS)
        image.paste(resized_logo, (spec["pad"], spec["header_y"] + 2), resized_logo)

    title_x = spec["pad"] + logo_w + 16
    _draw_text((title_x, spec["header_y"]), "Trifecta Card", spec["title_font"], FG)
    _draw_text((title_x, spec["header_y"] + 46), SUBTITLE_TEXT, spec["subtitle_font"], DIM)

    # Top-right date window + call count (if room beside title, else below)
    meta_w = draw.textlength(spec["meta_line"], font=spec["meta_font"])
    meta_x = width - spec["pad"] - meta_w
    _draw_text((meta_x, spec["header_y"] + 10), spec["meta_line"], spec["meta_font"], DIM)

    # Verdict banner
    vx0, vy0 = spec["pad"], spec["verdict_y"]
    vx1, vy1 = width - spec["pad"], spec["verdict_y"] + spec["verdict_h"]
    v_fill = RED_BG if spec["is_risk"] else NEUTRAL_BG
    v_border = RED_BORDER if spec["is_risk"] else BORDER
    v_fg = RED if spec["is_risk"] else FG
    draw.rounded_rectangle([vx0, vy0, vx1, vy1], radius=12, fill=v_fill, outline=v_border, width=2)

    if spec["is_square"]:
        _draw_text((vx0 + 24, vy0 + 18), spec["verdict_text"], spec["verdict_title_font"], v_fg)
        _draw_text((vx0 + 24, vy0 + 60), spec["rate_text"], spec["verdict_rate_font"], FG)
    else:
        _draw_text((vx0 + 24, vy0 + 26), spec["verdict_text"], spec["verdict_title_font"], v_fg)
        rate_w = draw.textlength(spec["rate_text"], font=spec["verdict_rate_font"])
        _draw_text(
            (vx1 - 24 - rate_w, vy0 + 29),
            spec["rate_text"],
            spec["verdict_rate_font"],
            FG,
        )

    # Three equal-height vector tiles (neutral styling; red reserved for risk banner)
    for tile in spec["tiles"]:
        tx0, ty0, tx1, ty1 = tile["x0"], tile["y0"], tile["x1"], tile["y1"]
        draw.rounded_rectangle(
            [tx0, ty0, tx1, ty1], radius=12, fill=PANEL, outline=BORDER, width=1
        )
        _draw_text((tx0 + 20, ty0 + 20), tile["label"], spec["tile_label_font"], FG)
        num_y = ty0 + (62 if not spec["is_square"] else 76)
        _draw_text((tx0 + 20, num_y), tile["count_text"], spec["tile_num_font"], FG)
        sub_y = num_y + (66 if not spec["is_square"] else 84)
        _draw_text((tx0 + 20, sub_y), tile["sub_text"], spec["tile_sub_font"], DIM)

        # Dedicated non-wrapping example bar at bottom of tile
        ex_box_y0 = ty1 - 50
        draw.rounded_rectangle(
            [tx0 + 14, ex_box_y0, tx1 - 14, ty1 - 14],
            radius=8,
            fill=PANEL_ALT,
        )
        _draw_text((tx0 + 22, ex_box_y0 + 10), tile["example_text"], spec["tile_ex_font"], DIM)

    # Footer
    _draw_text((spec["pad"], spec["footer_y1"]), spec["footer_left_top"], spec["footer_font"], DIM)
    _draw_text((spec["pad"], spec["footer_y2"]), spec["repo_text"], spec["footer_mono_font"], DIM)
    verify_w = draw.textlength(spec["verify_cmd"], font=spec["footer_mono_font"])
    _draw_text(
        (width - spec["pad"] - verify_w, spec["footer_y2"]),
        spec["verify_cmd"],
        spec["footer_mono_font"],
        ACCENT,
    )

    Path(path).parent.mkdir(parents=True, exist_ok=True)
    image.save(str(path), format="PNG")
    return bounds


# ---------------------------------------------------------------------------
# SVG companion (same layout template)
# ---------------------------------------------------------------------------


def _svg_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def render_card_svg(
    report: Report,
    path,
    *,
    size: tuple[int, int] = SOCIAL_SIZE,
    logo_path: Path | str | None = None,
) -> None:
    width, height = size
    resolved_logo = _resolve_logo_path(logo_path)
    probe = ImageDraw.Draw(Image.new("RGB", (width, height), BG))
    json_name = Path(path).with_suffix(".json").name
    spec = _build_layout_spec(report, width, height, json_name, probe)

    with Image.open(resolved_logo) as raw_logo:
        logo_w = max(1, round(spec["logo_h"] * (raw_logo.width / raw_logo.height)))
    logo_b64 = base64.b64encode(resolved_logo.read_bytes()).decode("ascii")

    sans = "DejaVu Sans, Liberation Sans, Arial, sans-serif"
    mono = "DejaVu Sans Mono, Liberation Mono, Menlo, monospace"
    top_bar = _hex(RED if spec["is_risk"] else BORDER)

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">',
        f'<rect width="{width}" height="{height}" fill="{_hex(BG)}"/>',
        f'<rect x="0" y="0" width="{width}" height="6" fill="{top_bar}"/>',
        f'<image x="{spec["pad"]}" y="{spec["header_y"] + 2}" width="{logo_w}" '
        f'height="{spec["logo_h"]}" href="data:image/png;base64,{logo_b64}"/>',
    ]

    title_x = spec["pad"] + logo_w + 16
    parts.append(
        f'<text x="{title_x}" y="{spec["header_y"] + 34}" font-family="{sans}" '
        f'font-size="{36 if not spec["is_square"] else 42}" font-weight="bold" fill="{_hex(FG)}">'
        f"Trifecta Card</text>"
    )
    parts.append(
        f'<text x="{title_x}" y="{spec["header_y"] + 64}" font-family="{sans}" '
        f'font-size="{18 if not spec["is_square"] else 20}" fill="{_hex(DIM)}">'
        f"{_svg_escape(SUBTITLE_TEXT)}</text>"
    )
    parts.append(
        f'<text x="{width - spec["pad"]}" y="{spec["header_y"] + 24}" text-anchor="end" '
        f'font-family="{mono}" font-size="{15 if not spec["is_square"] else 17}" fill="{_hex(DIM)}">'
        f"{_svg_escape(spec['meta_line'])}</text>"
    )

    vx0, vy0 = spec["pad"], spec["verdict_y"]
    vw = width - 2 * spec["pad"]
    v_fill = _hex(RED_BG if spec["is_risk"] else NEUTRAL_BG)
    v_border = _hex(RED_BORDER if spec["is_risk"] else BORDER)
    v_fg = _hex(RED if spec["is_risk"] else FG)
    parts.append(
        f'<rect x="{vx0}" y="{vy0}" width="{vw}" height="{spec["verdict_h"]}" rx="12" '
        f'fill="{v_fill}" stroke="{v_border}" stroke-width="2"/>'
    )
    if spec["is_square"]:
        parts.append(
            f'<text x="{vx0 + 24}" y="{vy0 + 44}" font-family="{sans}" font-size="28" '
            f'font-weight="bold" fill="{v_fg}">{_svg_escape(spec["verdict_text"])}</text>'
        )
        parts.append(
            f'<text x="{vx0 + 24}" y="{vy0 + 82}" font-family="{mono}" font-size="22" '
            f'fill="{_hex(FG)}">{_svg_escape(spec["rate_text"])}</text>'
        )
    else:
        parts.append(
            f'<text x="{vx0 + 24}" y="{vy0 + 50}" font-family="{sans}" font-size="24" '
            f'font-weight="bold" fill="{v_fg}">{_svg_escape(spec["verdict_text"])}</text>'
        )
        parts.append(
            f'<text x="{width - spec["pad"] - 24}" y="{vy0 + 49}" text-anchor="end" '
            f'font-family="{mono}" font-size="20" fill="{_hex(FG)}">'
            f"{_svg_escape(spec['rate_text'])}</text>"
        )

    for tile in spec["tiles"]:
        tx0, ty0, tx1, ty1 = tile["x0"], tile["y0"], tile["x1"], tile["y1"]
        tw, th = tx1 - tx0, ty1 - ty0
        parts.append(
            f'<rect x="{tx0}" y="{ty0}" width="{tw}" height="{th}" rx="12" '
            f'fill="{_hex(PANEL)}" stroke="{_hex(BORDER)}" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{tx0 + 20}" y="{ty0 + 38}" font-family="{sans}" '
            f'font-size="{18 if not spec["is_square"] else 20}" font-weight="bold" '
            f'fill="{_hex(FG)}">{_svg_escape(tile["label"])}</text>'
        )
        num_y = ty0 + (108 if not spec["is_square"] else 136)
        parts.append(
            f'<text x="{tx0 + 20}" y="{num_y}" font-family="{mono}" '
            f'font-size="{48 if not spec["is_square"] else 64}" font-weight="bold" '
            f'fill="{_hex(FG)}">{_svg_escape(tile["count_text"])}</text>'
        )
        sub_y = num_y + (28 if not spec["is_square"] else 34)
        parts.append(
            f'<text x="{tx0 + 20}" y="{sub_y}" font-family="{sans}" '
            f'font-size="{15 if not spec["is_square"] else 17}" fill="{_hex(DIM)}">'
            f"{_svg_escape(tile['sub_text'])}</text>"
        )
        ex_box_y0 = ty1 - 50
        parts.append(
            f'<rect x="{tx0 + 14}" y="{ex_box_y0}" width="{tw - 28}" height="36" rx="8" '
            f'fill="{_hex(PANEL_ALT)}"/>'
        )
        parts.append(
            f'<text x="{tx0 + 22}" y="{ex_box_y0 + 23}" font-family="{sans}" '
            f'font-size="{14 if not spec["is_square"] else 16}" fill="{_hex(DIM)}">'
            f"{_svg_escape(tile['example_text'])}</text>"
        )

    parts.append(
        f'<text x="{spec["pad"]}" y="{spec["footer_y1"] + 14}" font-family="{sans}" '
        f'font-size="{14 if not spec["is_square"] else 15}" fill="{_hex(DIM)}">'
        f"{_svg_escape(spec['footer_left_top'])}</text>"
    )
    parts.append(
        f'<text x="{spec["pad"]}" y="{spec["footer_y2"] + 13}" font-family="{mono}" '
        f'font-size="{13 if not spec["is_square"] else 14}" fill="{_hex(DIM)}">'
        f"{_svg_escape(spec['repo_text'])}</text>"
    )
    parts.append(
        f'<text x="{width - spec["pad"]}" y="{spec["footer_y2"] + 13}" text-anchor="end" '
        f'font-family="{mono}" font-size="{13 if not spec["is_square"] else 14}" '
        f'fill="{_hex(ACCENT)}">{_svg_escape(spec["verify_cmd"])}</text>'
    )
    parts.append("</svg>")

    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("\n".join(parts) + "\n", encoding="utf-8")


def render_card_files(
    report: Report,
    out_png,
    *,
    logo_path: Path | str | None = None,
) -> dict:
    """Write card.png (1200x630), card-square.png (1080x1080), card.svg, and card.json."""
    out_png = Path(out_png)
    if out_png.suffix.lower() != ".png":
        out_png = out_png.with_suffix(".png")
    out_square = out_png.with_name(f"{out_png.stem}-square.png")
    out_svg = out_png.with_suffix(".svg")
    out_json = out_png.with_suffix(".json")
    render_card_png(report, out_png, size=SOCIAL_SIZE, logo_path=logo_path)
    render_card_png(report, out_square, size=SQUARE_SIZE, logo_path=logo_path)
    render_card_svg(report, out_svg, size=SOCIAL_SIZE, logo_path=logo_path)
    from receiptd.card.signing import write_signed_card

    write_signed_card(report, out_json)
    return {
        "png": str(out_png),
        "square_png": str(out_square),
        "svg": str(out_svg),
        "json": str(out_json),
    }
