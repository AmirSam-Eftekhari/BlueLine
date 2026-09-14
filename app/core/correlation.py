"""
Finding correlation engine.

Different analyzers can report the same underlying weakness (e.g. the
static analyzer flags a suspected command-injection call, and the
fuzzer later crashes that exact code path). This groups findings that
share a fingerprint (category + subcategory + affected_component +
location) into one root issue with merged evidence and preserved
detector attribution, so the report isn't a pile of duplicates.
"""

from __future__ import annotations

from app.core.models import Finding, ValidationStatus


class FindingCorrelator:
    def correlate(self, findings: list[Finding]) -> list[Finding]:
        groups: dict[str, list[Finding]] = {}
        for f in findings:
            groups.setdefault(f.fingerprint, []).append(f)

        merged: list[Finding] = []
        for fingerprint, group in groups.items():
            if len(group) == 1:
                merged.append(group[0])
                continue
            primary = max(group, key=lambda f: f.confidence)
            all_sources = sorted({s for f in group for s in f.detector_sources})
            all_evidence = [e for f in group for e in f.evidence]

            # If one analyzer says CONFIRMED (e.g. dynamic/fuzz reproduction)
            # and another says SUSPECTED (static heuristic), the merged
            # finding is CONFIRMED — corroboration is exactly what raises
            # confidence from a heuristic guess to a proven issue.
            statuses = [f.validation_status for f in group]
            if ValidationStatus.CONFIRMED in statuses:
                primary.validation_status = ValidationStatus.CONFIRMED
                primary.confidence = max(f.confidence for f in group)
            elif ValidationStatus.PROBABLE in statuses:
                primary.validation_status = ValidationStatus.PROBABLE

            primary.detector_sources = all_sources
            primary.evidence = all_evidence
            primary.title = f"{primary.title} (corroborated by {len(all_sources)} detectors)" \
                if len(all_sources) > 1 else primary.title
            merged.append(primary)

        return merged
