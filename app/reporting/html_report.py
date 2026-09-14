"""
HTML report generator.

Produces a single self-contained HTML file (inline CSS, no CDN/network
dependency — this is an offline-first product) covering: executive
summary, target profile, scan configuration, coverage, severity
distribution, findings with evidence, risk breakdown, remediation,
limitations, and environment/timestamp metadata.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone

from app.core.models import ScanResult, Severity
from app.reporting.charts import coverage_bars_svg, severity_donut_svg, severity_legend_svg

SEVERITY_COLORS = {
    "CRITICAL": "#b91c1c", "HIGH": "#c2410c", "MEDIUM": "#a16207",
    "LOW": "#3f6212", "INFORMATIONAL": "#334155",
}

CSS = """
:root { --blue: #1d4ed8; --bg: #0b1220; --panel:#111a2e; --text:#e5e9f2; --muted:#93a0b8; --line:#233150; }
* { box-sizing: border-box; }
body { background: var(--bg); color: var(--text); font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
       margin:0; padding:0; line-height:1.5; }
.container { max-width: 1080px; margin: 0 auto; padding: 32px 24px 80px; }
header.brand { display:flex; align-items:center; gap:14px; padding: 28px 0 20px; border-bottom:1px solid var(--line); }
header.brand svg { width:40px; height:40px; }
header.brand h1 { font-size: 22px; margin:0; letter-spacing: 0.3px; }
header.brand p { margin:2px 0 0; color: var(--muted); font-size: 13px; }
h2.section { font-size:15px; text-transform:uppercase; letter-spacing:1px; color: var(--blue);
             border-bottom:1px solid var(--line); padding-bottom:8px; margin-top:44px; }
.grid { display:flex; flex-wrap:wrap; gap:14px; margin-top:16px; }
.grid .card { flex: 1 1 190px; min-width:150px; }
.card { background: var(--panel); border:1px solid var(--line); border-radius:10px; padding:16px; }
.card .label { color: var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:0.5px; }
.card .value { font-size:26px; font-weight:600; margin-top:6px; }
table { width:100%; border-collapse:collapse; margin-top:14px; font-size:13.5px; }
th, td { text-align:left; padding:10px 12px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color: var(--muted); font-weight:600; font-size:12px; text-transform:uppercase; }
.badge { display:inline-block; padding:2px 9px; border-radius:999px; font-size:11.5px; font-weight:700;
         color:#fff; }
.finding { background: var(--panel); border:1px solid var(--line); border-radius:10px; padding:18px 20px;
           margin-top:16px; }
.finding h3 { margin:0 0 6px; font-size:16px; }
.meta { display:flex; gap:18px; flex-wrap:wrap; color: var(--muted); font-size:12.5px; margin-bottom:10px; }
.meta span { margin-right: 18px; display:inline-block; } /* fallback for renderers without flexbox gap support */
pre.snippet { background:#060a14; border:1px solid var(--line); border-radius:8px; padding:12px 14px;
              overflow-x:auto; font-size:12.5px; color:#c9d4e8; }
.note { color: var(--muted); font-size:13px; margin-top:8px; }
.limits { background: var(--panel); border:1px dashed var(--line); border-radius:10px; padding:16px 18px;
          color: var(--muted); font-size:13.5px; }
footer { color: var(--muted); font-size:12px; margin-top:60px; border-top:1px solid var(--line); padding-top:16px; }
"""

LOGO_SVG = """
<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M24 4 L42 12 V24 C42 34 34.5 41.5 24 44 C13.5 41.5 6 34 6 24 V12 Z"
        fill="#0f1b33" stroke="#1d4ed8" stroke-width="2"/>
  <path d="M12 24 H20 L24 15 L28 33 L32 24 H36" stroke="#3b82f6" stroke-width="2.4"
        stroke-linecap="round" stroke-linejoin="round" fill="none"/>
</svg>
"""


def _esc(s) -> str:
    return html.escape(str(s)) if s is not None else ""


def generate_html_report(result: ScanResult) -> str:
    profile = result.target_profile
    counts = result.severity_counts()
    findings_sorted = sorted(result.findings, key=lambda f: (-f.severity.rank, -(f.risk_score or 0)))

    stat_cards = "".join(
        f'<div class="card"><div class="label">{sev}</div>'
        f'<div class="value" style="color:{SEVERITY_COLORS[sev]}">{counts[sev]}</div></div>'
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    )
    severity_chart_html = f"""
    <div style="display:flex; align-items:center; gap:28px; margin-top:18px;">
      {severity_donut_svg(counts)}
      {severity_legend_svg(counts)}
    </div>"""

    coverage_chart_html = coverage_bars_svg(result.coverage.get("by_stage", {}))

    coverage_rows = "".join(
        f"<tr><td>{_esc(stage)}</td><td>{'N/A (skipped)' if v is None else f'{v}%'}</td></tr>"
        for stage, v in result.coverage.get("by_stage", {}).items()
    )

    stage_rows = "".join(
        f"<tr><td>{_esc(s.stage_name)}</td><td>{_esc(s.status)}</td>"
        f"<td>{_esc(s.findings_count)}</td><td>{_esc(s.error or '')}</td></tr>"
        for s in result.stage_results
    )

    finding_blocks = []
    for f in findings_sorted:
        evidence_html = "".join(
            f'<pre class="snippet">{_esc(e.snippet or e.raw_output or e.description)}</pre>'
            for e in f.evidence
        )
        finding_blocks.append(f"""
        <div class="finding">
          <h3>{_esc(f.title)} <span style="color:var(--muted); font-weight:400; font-size:13px;">[{_esc(f.id)}]</span></h3>
          <div class="meta">
            <span class="badge" style="background:{SEVERITY_COLORS[f.severity.value]}">{_esc(f.severity.value)}</span>
            <span>Risk score: <b>{_esc(f.risk_score if f.risk_score is not None else 'n/a')}</b></span>
            <span>Confidence: <b>{_esc(f.confidence)}%</b></span>
            <span>Validation: <b>{_esc(f.validation_status.value)}</b></span>
            <span>Category: {_esc(f.category)} / {_esc(f.subcategory)}</span>
            <span>Location: {_esc(f.location or f.affected_component)}</span>
            <span>Detected by: {_esc(', '.join(f.detector_sources))}</span>
          </div>
          {evidence_html}
          <p><b>Impact:</b> {_esc(f.impact)}</p>
          <p><b>Remediation:</b> {_esc(f.remediation)}</p>
          {f'<p><b>Reproduction:</b> {_esc(f.reproduction)}</p>' if f.reproduction else ''}
        </div>""")

    capabilities_rows = "".join(
        f"<tr><td>{_esc(c.name)}</td><td>{_esc(c.level.value)}</td><td>{_esc(c.notes)}</td></tr>"
        for c in profile.capabilities
    )

    total = len(result.findings)
    if total == 0:
        exec_summary = ("No confirmed findings were identified within the analyzed attack surface and "
                         "available capabilities. This does not mean the target is secure — see Coverage "
                         "and Limitations below for what was and was not tested.")
    else:
        exec_summary = (
            f"{total} finding(s) were identified: {counts['CRITICAL']} critical, {counts['HIGH']} high, "
            f"{counts['MEDIUM']} medium, {counts['LOW']} low, {counts['INFORMATIONAL']} informational. "
            f"Overall assessment coverage was {result.coverage.get('overall_assessment_coverage', 'n/a')}%. "
            "This report distinguishes severity, confidence, and validation status for every finding — "
            "review the Limitations section before treating any UNVERIFIED/SUSPECTED item as confirmed."
        )

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<title>BlueLine Assessment Report — {_esc(profile.target_path)}</title>
<style>{CSS}</style></head>
<body><div class="container">

<header class="brand">
  {LOGO_SVG}
  <div><h1>BlueLine</h1><p>Universal Security &amp; Reliability Assessment Platform — Report</p></div>
</header>

<h2 class="section">Executive Summary</h2>
<p>{_esc(exec_summary)}</p>
<div class="grid">{stat_cards}</div>
{severity_chart_html}

<h2 class="section">Target Profile</h2>
<table>
<tr><th>Target</th><td>{_esc(profile.target_path)}</td></tr>
<tr><th>Type</th><td>{_esc(profile.target_type)}</td></tr>
<tr><th>Languages</th><td>{_esc(', '.join(profile.languages) or 'none detected')}</td></tr>
<tr><th>Build systems</th><td>{_esc(', '.join(profile.build_systems) or 'none detected')}</td></tr>
<tr><th>Package managers</th><td>{_esc(', '.join(profile.package_managers) or 'none detected')}</td></tr>
<tr><th>Dependencies (approx.)</th><td>{_esc(profile.dependencies_count)}</td></tr>
<tr><th>Interfaces</th><td>{_esc(', '.join(profile.interfaces) or 'none detected')}</td></tr>
<tr><th>Files scanned</th><td>{_esc(profile.file_count)}</td></tr>
</table>

<h2 class="section">Declared Capabilities</h2>
<table><tr><th>Capability</th><th>Support Level</th><th>Notes</th></tr>{capabilities_rows}</table>

<h2 class="section">Scan Configuration</h2>
<table>
<tr><th>Profile</th><td>{_esc(result.config.profile)}</td></tr>
<tr><th>Dynamic analysis</th><td>{_esc(result.config.enable_dynamic)}</td></tr>
<tr><th>Fuzzing</th><td>{_esc(result.config.enable_fuzzing)} (max cases: {_esc(result.config.fuzz_max_cases)})</td></tr>
<tr><th>Started</th><td>{_esc(result.started_at)}</td></tr>
<tr><th>Finished</th><td>{_esc(result.finished_at)}</td></tr>
</table>

<h2 class="section">Analysis Coverage</h2>
{coverage_chart_html}
<table><tr><th>Stage</th><th>Coverage</th></tr>{coverage_rows}</table>
<p class="note">Overall assessment coverage: <b>{_esc(result.coverage.get('overall_assessment_coverage'))}%</b>.
{_esc(result.coverage.get('note',''))}</p>

<h2 class="section">Stage Execution Log</h2>
<table><tr><th>Stage</th><th>Status</th><th>Findings</th><th>Error</th></tr>{stage_rows}</table>

<h2 class="section">Findings ({total})</h2>
{''.join(finding_blocks) if finding_blocks else '<p class="note">No findings to display.</p>'}

<h2 class="section">Limitations</h2>
<div class="limits">
<p>BlueLine reports what it actually tested, not a universal guarantee. Known limitations of this
build: JavaScript/TypeScript analysis is heuristic/pattern-based, not full AST/type-flow analysis.
C/C++ analysis is experimental pattern-matching on a small set of unsafe libc calls. Dependency
checks run against a small local curated sample of historical vulnerabilities, not a live feed —
absence of a finding does not mean a dependency has no known vulnerabilities. Fuzzing is black-box
(no code-coverage feedback). BlueLine never asserts a target is "100% secure."</p>
</div>

<footer>Generated by BlueLine on {generated_at} · Scan ID: {_esc(result.scan_id)}</footer>
</div></body></html>"""
