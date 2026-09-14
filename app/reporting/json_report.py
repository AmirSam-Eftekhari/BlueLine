"""JSON and SARIF report generators."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from app.core.models import ScanResult

SARIF_SEVERITY_MAP = {
    "CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
    "LOW": "note", "INFORMATIONAL": "note",
}


def generate_json_report(result: ScanResult) -> str:
    return json.dumps(result.as_dict(), indent=2)


def generate_sarif_report(result: ScanResult) -> str:
    """SARIF 2.1.0 output for CI/developer tool integration."""
    rules = {}
    sarif_results = []

    for f in result.findings:
        rule_id = f"{f.category}/{f.subcategory}".replace(" ", "_")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.impact or f.title},
                "help": {"text": f.remediation or ""},
            }

        loc = []
        if f.location and ":" in f.location:
            path, _, line = f.location.rpartition(":")
            try:
                line_num = int(line)
            except ValueError:
                line_num = 1
            loc.append({
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {"startLine": max(1, line_num)},
                }
            })

        sarif_results.append({
            "ruleId": rule_id,
            "level": SARIF_SEVERITY_MAP.get(f.severity.value, "warning"),
            "message": {"text": f"{f.title} (confidence {f.confidence}%, validation "
                                 f"{f.validation_status.value})"},
            "locations": loc,
            "properties": {
                "severity": f.severity.value,
                "confidence": f.confidence,
                "validationStatus": f.validation_status.value,
                "riskScore": f.risk_score,
                "detectionMethod": f.detection_method.value,
            },
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "BlueLine",
                    "informationUri": "https://example.invalid/blueline",
                    "version": "0.1.0",
                    "rules": list(rules.values()),
                }
            },
            "results": sarif_results,
            "properties": {
                "coverage": result.coverage,
                "scanId": result.scan_id,
                "generatedAt": datetime.now(timezone.utc).isoformat(),
            },
        }],
    }
    return json.dumps(sarif, indent=2)
