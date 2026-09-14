"""
Coverage engine.

BlueLine must never say "the system is secure." This module computes
what fraction of the applicable analysis surface was actually covered,
per category, from real stage outcomes — not an assumed 100%.
"""

from __future__ import annotations

from app.core.models import StageResult, TargetProfile


class CoverageEngine:
    def compute(self, profile: TargetProfile, stage_results: list[StageResult]) -> dict:
        by_stage = {s.stage_name: s for s in stage_results}
        coverage: dict[str, float] = {}

        for stage_name, stage in by_stage.items():
            if stage.status == "completed":
                coverage[stage_name] = round(max(0.0, 100.0 - stage.coverage_impact), 1)
            elif stage.status == "partial":
                coverage[stage_name] = round(max(0.0, 60.0 - stage.coverage_impact), 1)
            elif stage.status == "failed":
                coverage[stage_name] = 0.0
            else:  # skipped
                coverage[stage_name] = None

        measured = [v for v in coverage.values() if v is not None]
        overall = round(sum(measured) / len(measured), 1) if measured else 0.0

        unsupported = [c.name for c in profile.capabilities if c.level.value == "UNSUPPORTED"]

        return {
            "by_stage": coverage,
            "overall_assessment_coverage": overall,
            "unsupported_capabilities": unsupported,
            "note": (
                "Coverage reflects what was actually executed and validated, not an assumption of "
                "completeness. A high coverage percentage means the applicable analyzers ran "
                "successfully across the applicable surface — it does not mean no vulnerabilities "
                "remain outside that surface."
            ),
        }
