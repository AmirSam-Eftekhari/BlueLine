"""CSV export — one row per finding, for spreadsheet triage."""

from __future__ import annotations

import csv
import io

from app.core.models import ScanResult

FIELDS = ["id", "title", "category", "subcategory", "severity", "confidence",
          "validation_status", "risk_score", "location", "affected_component",
          "detection_method", "remediation"]


def generate_csv_report(result: ScanResult) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=FIELDS, extrasaction="ignore")
    writer.writeheader()
    for f in result.findings:
        row = f.as_dict()
        row["severity"] = row["severity"]
        writer.writerow(row)
    return buf.getvalue()
