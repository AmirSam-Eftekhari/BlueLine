import unittest
from pathlib import Path
from unittest import mock

from app.core.models import ScanConfig
from app.core.orchestrator import ScanOrchestrator
from app.reporting.pdf_report import PdfGenerationError, generate_pdf_report, wkhtmltopdf_available

FIXTURE = str(Path(__file__).resolve().parent.parent / "test-targets" / "vulnerable-python")


class TestPdfReport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        orch = ScanOrchestrator()
        cls.result = orch.run_scan("pdf_report_test", FIXTURE, ScanConfig.for_profile("standard"))

    def test_wkhtmltopdf_is_available_in_this_environment(self):
        # This project's dev environment has wkhtmltopdf installed (it's
        # also what was used to visually QA the HTML report elsewhere in
        # this test suite's development) — confirms the "happy path" test
        # below is exercising the real conversion, not silently skipping it.
        self.assertTrue(wkhtmltopdf_available())

    def test_generates_a_real_valid_pdf(self):
        pdf_bytes = generate_pdf_report(self.result)
        self.assertGreater(len(pdf_bytes), 1000, "PDF suspiciously small — likely not real content")
        self.assertEqual(pdf_bytes[:4], b"%PDF", "Output doesn't start with the PDF magic bytes")

    def test_pdf_contains_real_finding_count_reflected_in_size(self):
        # Not a rigorous content check (would need a PDF text extractor,
        # an extra dependency), but a scan with findings should produce
        # a meaningfully larger PDF than an empty-findings one — a cheap
        # sanity signal that real content, not a boilerplate error page,
        # was rendered.
        empty_result = ScanOrchestrator().run_scan(
            "pdf_empty_test", FIXTURE, ScanConfig.for_profile("quick"))
        empty_result.findings = []
        small_pdf = generate_pdf_report(empty_result)
        full_pdf = generate_pdf_report(self.result)
        self.assertGreater(len(full_pdf), len(small_pdf))

    def test_raises_clear_error_when_wkhtmltopdf_missing(self):
        with mock.patch("app.reporting.pdf_report.shutil.which", return_value=None):
            with self.assertRaises(PdfGenerationError) as ctx:
                generate_pdf_report(self.result)
            self.assertIn("wkhtmltopdf", str(ctx.exception))
            self.assertIn("install", str(ctx.exception).lower())

    def test_never_raises_a_bare_unrelated_exception(self):
        # Regardless of failure mode, callers should only ever need to
        # catch PdfGenerationError, never a raw subprocess/OSError leaking through.
        with mock.patch("app.reporting.pdf_report.subprocess.run",
                         side_effect=OSError("simulated failure")):
            with self.assertRaises(PdfGenerationError):
                generate_pdf_report(self.result)


if __name__ == "__main__":
    unittest.main()
