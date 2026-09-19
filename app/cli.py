"""
BlueLine CLI.

    blueline scan <target> [--profile quick|standard|deep|maximum] [--out report.html]
    blueline report <scan_id> [--format html|json|sarif|csv|pdf] [--out path]
    blueline compare <scan_id_a> <scan_id_b>
    blueline history [--target <path>]

Exit codes are CI-friendly: 0 = completed with no HIGH/CRITICAL findings,
1 = completed with HIGH/CRITICAL findings, 2 = scan error.
"""

from __future__ import annotations

import sys
import uuid

import click

from app.core import paths
from app.core.logging_setup import log_structured
from app.core.models import ScanConfig
from app.core.orchestrator import ScanOrchestrator
from app.persistence.store import ScanStore
from app.reporting.csv_report import generate_csv_report
from app.reporting.html_report import generate_html_report
from app.reporting.json_report import generate_json_report, generate_sarif_report

DEFAULT_DB_PATH = paths.default_db_path()


def _progress_printer(stage, status, detail):
    marker = {"running": "…", "completed": "✓", "failed": "✗", "skipped": "-"}.get(status, "?")
    extra = ""
    if status == "completed" and "findings" in detail:
        extra = f" ({detail['findings']} findings)"
    if status == "failed":
        extra = f" ({detail.get('error','')})"
    click.echo(f"  [{marker}] {stage}{extra}")


@click.group()
def cli():
    """BlueLine — Universal Security & Reliability Assessment Platform."""
    pass


@cli.command()
@click.argument("target")
@click.option("--profile", type=click.Choice(["quick", "standard", "deep", "maximum"]), default="standard")
@click.option("--db", default=DEFAULT_DB_PATH, help="Path to local scan database.")
@click.option("--out", default=None, help="Write an HTML report to this path after the scan.")
def scan(target, profile, db, out):
    """Run a scan against TARGET (a file or directory)."""
    scan_id = f"scan_{uuid.uuid4().hex[:10]}"
    config = ScanConfig.for_profile(profile)
    log_structured("app", "Scan requested via CLI", scan_id=scan_id, target=target, profile=profile)
    click.echo(f"BlueLine scan {scan_id}  target={target}  profile={profile}")

    orchestrator = ScanOrchestrator()
    result = orchestrator.run_scan(scan_id, target, config, progress=_progress_printer)

    store = ScanStore(db)
    store.save(result)
    store.close()

    counts = result.severity_counts()
    click.echo("")
    click.echo(f"Scan {result.status}. Severity counts: {counts}")
    click.echo(f"Overall assessment coverage: {result.coverage.get('overall_assessment_coverage')}%")
    click.echo(f"Scan ID: {scan_id}  (use `blueline report {scan_id}` for a full report)")

    if out:
        with open(out, "w") as fh:
            fh.write(generate_html_report(result))
        click.echo(f"HTML report written to {out}")

    if counts["CRITICAL"] > 0 or counts["HIGH"] > 0:
        sys.exit(1)
    sys.exit(0)


@cli.command()
@click.argument("scan_id")
@click.option("--format", "fmt", type=click.Choice(["html", "json", "sarif", "csv", "pdf"]), default="html")
@click.option("--out", default=None)
@click.option("--db", default=DEFAULT_DB_PATH)
def report(scan_id, fmt, out, db):
    """Generate a report for a previously completed SCAN_ID."""
    from app.reporting.pdf_report import PdfGenerationError, generate_pdf_report
    store = ScanStore(db)
    data = store.load(scan_id)
    store.close()
    if not data:
        click.echo(f"No scan found with ID {scan_id}", err=True)
        sys.exit(2)

    result = _scan_result_from_dict(data)
    if fmt == "html":
        content = generate_html_report(result)
    elif fmt == "json":
        content = generate_json_report(result)
    elif fmt == "sarif":
        content = generate_sarif_report(result)
    elif fmt == "pdf":
        try:
            content = generate_pdf_report(result)
        except PdfGenerationError as e:
            click.echo(f"Could not generate PDF: {e}", err=True)
            sys.exit(2)
    else:
        content = generate_csv_report(result)

    out = out or f"{scan_id}.{fmt if fmt != 'sarif' else 'sarif.json'}"
    mode = "wb" if fmt == "pdf" else "w"
    with open(out, mode) as fh:
        fh.write(content)
    click.echo(f"Report written to {out}")


@cli.command()
@click.argument("scan_id_a")
@click.argument("scan_id_b")
@click.option("--db", default=DEFAULT_DB_PATH)
def compare(scan_id_a, scan_id_b, db):
    """Compare two scans (regression analysis)."""
    store = ScanStore(db)
    diff = store.compare(scan_id_a, scan_id_b)
    store.close()
    click.echo(f"Previous: {diff['severity_counts_previous']}")
    click.echo(f"Current:  {diff['severity_counts_current']}")
    click.echo(f"New findings: {len(diff['new_findings'])}")
    click.echo(f"Resolved findings: {len(diff['resolved_findings'])}")
    click.echo(f"Worsened findings: {len(diff['worsened_findings'])}")
    for w in diff["worsened_findings"]:
        click.echo(f"  - {w['title']}: {w['from']} -> {w['to']}")


@cli.command()
@click.option("--target", default=None)
@click.option("--db", default=DEFAULT_DB_PATH)
def history(target, db):
    """List previous scans."""
    store = ScanStore(db)
    rows = store.list_history(target_path=target)
    store.close()
    for r in rows:
        click.echo(f"{r['scan_id']}  {r['started_at']}  {r['target_path']}  "
                   f"C:{r['critical_count']} H:{r['high_count']} M:{r['medium_count']} "
                   f"L:{r['low_count']}  coverage={r['overall_coverage']}%")


@cli.command()
@click.argument("scan_id", required=False)
@click.option("--all", "delete_all_flag", is_flag=True, default=False,
              help="Delete ALL scan history instead of a single scan.")
@click.option("--target", default=None,
              help="With --all, only delete history for this specific target path.")
@click.option("--yes", is_flag=True, default=False, help="Skip the confirmation prompt.")
@click.option("--db", default=DEFAULT_DB_PATH)
def delete(scan_id, delete_all_flag, target, yes, db):
    """Delete a scan from history, or clear all history with --all.

    Examples:
        blueline delete scan_968e1d8971
        blueline delete --all
        blueline delete --all --target /path/to/project
    """
    if not delete_all_flag and not scan_id:
        click.echo("Provide a SCAN_ID to delete, or pass --all to clear history.", err=True)
        sys.exit(2)
    if delete_all_flag and scan_id:
        click.echo("Pass either a SCAN_ID or --all, not both.", err=True)
        sys.exit(2)

    store = ScanStore(db)
    try:
        if delete_all_flag:
            scope = f" for target {target}" if target else ""
            if not yes:
                click.confirm(f"Delete ALL scan history{scope}? This cannot be undone.", abort=True)
            count = store.delete_all(target_path=target)
            click.echo(f"Deleted {count} scan(s){scope}.")
        else:
            if not yes:
                click.confirm(f"Delete scan {scan_id}? This cannot be undone.", abort=True)
            deleted = store.delete(scan_id)
            if deleted:
                click.echo(f"Deleted {scan_id}.")
            else:
                click.echo(f"No scan found with ID {scan_id} — nothing to delete.", err=True)
                sys.exit(2)
    finally:
        store.close()


def _scan_result_from_dict(data: dict):
    """Reconstruct a ScanResult-like object good enough for report generation
    from persisted JSON (avoids re-deriving full dataclasses from raw dicts
    by using a lightweight shim with the same attribute surface reports need)."""
    from types import SimpleNamespace
    from app.core.models import Severity, ValidationStatus, DetectionMethod, Finding, Evidence, \
        RiskFactors, TargetProfile, AnalyzerCapability, CapabilityLevel, ScanConfig, StageResult

    def mk_finding(fd):
        return Finding(
            id=fd["id"], title=fd["title"], category=fd["category"], subcategory=fd["subcategory"],
            severity=Severity(fd["severity"]), confidence=fd["confidence"],
            validation_status=ValidationStatus(fd["validation_status"]),
            affected_target=fd["affected_target"], affected_component=fd["affected_component"],
            location=fd["location"], detection_method=DetectionMethod(fd["detection_method"]),
            evidence=[Evidence(**e) for e in fd["evidence"]],
            observed_behavior=fd["observed_behavior"], expected_behavior=fd["expected_behavior"],
            impact=fd["impact"], reproduction=fd["reproduction"], remediation=fd["remediation"],
            references=fd["references"],
            risk_factors=RiskFactors(**fd["risk_factors"]) if fd.get("risk_factors") else None,
            risk_score=fd["risk_score"], first_seen=fd["first_seen"], last_seen=fd["last_seen"],
            detector_sources=fd["detector_sources"], fingerprint=fd["fingerprint"],
        )

    tp = data["target_profile"]
    profile = TargetProfile(
        target_path=tp["target_path"], target_type=tp["target_type"], languages=tp["languages"],
        build_systems=tp["build_systems"], package_managers=tp["package_managers"],
        dependencies_count=tp["dependencies_count"], entry_points=tp["entry_points"],
        config_files=tp["config_files"], interfaces=tp["interfaces"], executables=tp["executables"],
        test_suites_detected=tp["test_suites_detected"], container_definitions=tp["container_definitions"],
        file_count=tp["file_count"], total_size_bytes=tp["total_size_bytes"],
        capabilities=[AnalyzerCapability(c["name"], CapabilityLevel(c["level"]), c.get("notes", ""))
                      for c in tp["capabilities"]],
        discovery_warnings=tp["discovery_warnings"], discovered_at=tp["discovered_at"],
    )
    cfg = ScanConfig(**data["config"])
    stage_results = [StageResult(**s) for s in data["stage_results"]]

    result = SimpleNamespace(
        scan_id=data["scan_id"], target_profile=profile, config=cfg,
        findings=[mk_finding(f) for f in data["findings"]],
        stage_results=stage_results, coverage=data["coverage"],
        started_at=data["started_at"], finished_at=data["finished_at"], status=data["status"],
    )
    result.severity_counts = lambda: _counts(result.findings)
    result.as_dict = lambda: data
    return result


def _counts(findings):
    from app.core.models import Severity
    c = {s.value: 0 for s in Severity}
    for f in findings:
        c[f.severity.value] += 1
    return c


if __name__ == "__main__":
    cli()
