"""
SVG chart generation for BlueLine reports.

Hand-rolled SVG (no matplotlib/plotting dependency — keeps the offline
build lightweight). Every value drawn here comes from the caller's real
data; there is no placeholder/sample data path in this module.
"""

from __future__ import annotations

import math

SEVERITY_COLORS = {
    "CRITICAL": "#ef4444", "HIGH": "#f2994a", "MEDIUM": "#eab308",
    "LOW": "#22c55e", "INFORMATIONAL": "#7c8aa5",
}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]


def severity_donut_svg(counts: dict, size: int = 180) -> str:
    """A donut chart of severity counts. Returns an empty-state SVG if
    there are zero findings rather than drawing a misleading full circle."""
    total = sum(counts.get(s, 0) for s in SEVERITY_ORDER)
    cx = cy = size / 2
    r_outer = size / 2 - 10
    r_inner = r_outer * 0.62
    stroke_w = r_outer - r_inner

    if total == 0:
        return f"""<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}">
  <circle cx="{cx}" cy="{cy}" r="{(r_outer+r_inner)/2}" fill="none" stroke="#2f4166"
          stroke-width="{stroke_w}" stroke-dasharray="4 6"/>
  <text x="{cx}" y="{cy+5}" text-anchor="middle" font-size="13" fill="#7c8aa5"
        font-family="sans-serif">0 findings</text>
</svg>"""

    circumference = 2 * math.pi * ((r_outer + r_inner) / 2)
    r_mid = (r_outer + r_inner) / 2
    segments = []
    offset = 0.0
    for sev in SEVERITY_ORDER:
        count = counts.get(sev, 0)
        if count == 0:
            continue
        frac = count / total
        length = frac * circumference
        segments.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r_mid}" fill="none" stroke="{SEVERITY_COLORS[sev]}" '
            f'stroke-width="{stroke_w}" stroke-dasharray="{length:.2f} {circumference:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {cx} {cy})"/>'
        )
        offset += length

    return f"""<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}">
  {''.join(segments)}
  <text x="{cx}" y="{cy-2}" text-anchor="middle" font-size="22" font-weight="700" fill="#e7ecf6"
        font-family="sans-serif">{total}</text>
  <text x="{cx}" y="{cy+16}" text-anchor="middle" font-size="10.5" fill="#93a0ba"
        font-family="sans-serif">FINDINGS</text>
</svg>"""


def severity_legend_svg(counts: dict) -> str:
    rows = []
    for i, sev in enumerate(SEVERITY_ORDER):
        count = counts.get(sev, 0)
        rows.append(
            f'<g transform="translate(0 {i*20})">'
            f'<rect width="10" height="10" rx="2" fill="{SEVERITY_COLORS[sev]}"/>'
            f'<text x="16" y="9.5" font-size="11.5" fill="#c9d4e8" font-family="sans-serif">'
            f'{sev} ({count})</text></g>'
        )
    height = len(SEVERITY_ORDER) * 20
    return f'<svg viewBox="0 0 160 {height}" width="160" height="{height}">{"".join(rows)}</svg>'


def coverage_bars_svg(by_stage: dict, width: int = 480) -> str:
    """Horizontal bar per analysis stage. A skipped stage (value None) is
    drawn as a hollow/dashed bar rather than 0% or 100% — showing 'not
    run' as visually distinct from 'ran and found nothing left to cover'."""
    row_h = 26
    label_w = 190
    bar_w = width - label_w - 50
    height = max(1, len(by_stage)) * row_h + 10
    rows = []
    for i, (stage, value) in enumerate(by_stage.items()):
        y = i * row_h + 10
        label = stage if len(stage) <= 26 else stage[:24] + "…"
        if value is None:
            rows.append(f"""
  <text x="0" y="{y+13}" font-size="11.5" fill="#7c8aa5" font-family="sans-serif">{label}</text>
  <rect x="{label_w}" y="{y+2}" width="{bar_w}" height="12" rx="4" fill="none"
        stroke="#2f4166" stroke-dasharray="3 4"/>
  <text x="{label_w+bar_w+8}" y="{y+12}" font-size="11" fill="#5f6b85" font-family="sans-serif">skipped</text>""")
            continue
        pct = max(0.0, min(100.0, float(value)))
        color = "#22c55e" if pct >= 80 else "#eab308" if pct >= 40 else "#ef4444"
        fill_w = bar_w * pct / 100.0
        rows.append(f"""
  <text x="0" y="{y+13}" font-size="11.5" fill="#c9d4e8" font-family="sans-serif">{label}</text>
  <rect x="{label_w}" y="{y+2}" width="{bar_w}" height="12" rx="4" fill="#1a2337"/>
  <rect x="{label_w}" y="{y+2}" width="{fill_w:.1f}" height="12" rx="4" fill="{color}"/>
  <text x="{label_w+bar_w+8}" y="{y+12}" font-size="11" fill="#93a0ba" font-family="sans-serif">{pct:.0f}%</text>""")

    return f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}">{"".join(rows)}</svg>'
