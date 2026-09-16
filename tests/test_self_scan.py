"""
Dogfooding: BlueLine scans its own real source code.

This is a genuine quality gate, not a demonstration — if a future
change introduces something the Python analyzer would flag in
BlueLine's own codebase (a hardcoded secret, an eval(), a subprocess
shell=True), this test fails. It complements the fixture-based tests
elsewhere (which prove detection works against deliberately vulnerable
code) with the opposite check: that BlueLine's own real, production
code stays clean by the same rules it holds other targets to.

The one-time manual run of this exact scan (documented in
docs/ARCHITECTURE.md) found 17 MEDIUM findings, all from the
JS-INNERHTML pattern rule, and all confirmed by manual review to be
true negatives — every dynamic value reaching innerHTML in app.js goes
through the esc() escaping helper. That review is not re-done by this
automated test (it can't verify escaping any better than the analyzer
itself can), but the *count* is pinned so a change that adds a new,
unreviewed innerHTML usage is visible as a diff in this test rather
than silently accumulating unnoticed.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from app.core.models import ScanConfig
from app.core.orchestrator import ScanOrchestrator

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class TestSelfScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Copy only the real product code — not test-targets/ (deliberately
        # vulnerable fixtures) or tests/ — into an isolated temp directory,
        # so this scans exactly what ships, nothing else.
        cls.tmp = tempfile.TemporaryDirectory()
        dest = Path(cls.tmp.name) / "blueline_src"
        shutil.copytree(PROJECT_ROOT / "app", dest / "app")
        shutil.copytree(PROJECT_ROOT / "ui", dest / "ui")

        orch = ScanOrchestrator()
        cls.result = orch.run_scan("self_scan_test", str(dest), ScanConfig.for_profile("standard"))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_self_scan_completes_without_crashing(self):
        self.assertEqual(self.result.status, "completed")

    def test_no_stage_failed_scanning_our_own_code(self):
        failed = [s for s in self.result.stage_results if s.status == "failed"]
        self.assertEqual(failed, [], f"Analyzer stage(s) failed on BlueLine's own source: {failed}")

    def test_python_analyzer_finds_nothing_in_blueline_own_code(self):
        # This is the real regression guard: if a future change
        # introduces an eval(), a hardcoded secret, subprocess
        # shell=True, etc. into BlueLine's own Python code, this fails.
        py_findings = [f for f in self.result.findings if "python_static" in f.detector_sources]
        self.assertEqual(py_findings, [],
                          f"BlueLine's Python analyzer found issues in BlueLine's own code: "
                          f"{[(f.title, f.location) for f in py_findings]}")

    def test_no_critical_or_high_findings_in_our_own_code(self):
        # A softer, broader net than the Python-specific check above —
        # covers the JS analyzer too, at the severity level that matters
        # most. MEDIUM/LOW findings (like the reviewed innerHTML cases)
        # are expected and are not what this guards against.
        serious = [f for f in self.result.findings if f.severity.value in ("HIGH", "CRITICAL")]
        self.assertEqual(serious, [],
                          f"HIGH/CRITICAL findings in BlueLine's own code: "
                          f"{[(f.title, f.location) for f in serious]}")

    def test_coverage_is_complete_for_the_applicable_surface(self):
        self.assertEqual(self.result.coverage.get("overall_assessment_coverage"), 100.0)


if __name__ == "__main__":
    unittest.main()
