import unittest
from pathlib import Path

from app.analyzers.c_cpp_static import CCppStaticAnalyzer
from app.analyzers.js_static import JavaScriptStaticAnalyzer
from app.core.models import ScanConfig
from app.targets.discovery import TargetDiscovery
from app.core.orchestrator import ScanOrchestrator
from app.reporting.csv_report import generate_csv_report
from app.reporting.html_report import generate_html_report
from app.reporting.json_report import generate_json_report, generate_sarif_report

JS_FIXTURE = str(Path(__file__).resolve().parent.parent / "test-targets" / "vulnerable-javascript")
C_FIXTURE = str(Path(__file__).resolve().parent.parent / "test-targets" / "vulnerable-c")
PY_FIXTURE = str(Path(__file__).resolve().parent.parent / "test-targets" / "vulnerable-python")


class TestJavaScriptAnalyzer(unittest.TestCase):
    def test_detects_expected_categories(self):
        profile = TargetDiscovery().discover(JS_FIXTURE)
        analyzer = JavaScriptStaticAnalyzer()
        findings = analyzer.run(profile, ScanConfig.for_profile("standard"))
        categories = {f.category for f in findings}
        self.assertIn("Injection", categories)
        self.assertIn("Authentication", categories)  # JWT 'none' algorithm
        titles = {f.title for f in findings}
        self.assertTrue(any("eval" in t.lower() for t in titles))

    def test_declared_capability_is_partial_not_full(self):
        profile = TargetDiscovery().discover(JS_FIXTURE)
        analyzer = JavaScriptStaticAnalyzer()
        cap = analyzer.capability_for(profile)
        self.assertEqual(cap.level.value, "PARTIAL_SUPPORT",
                          "JS analyzer must never claim FULL_SUPPORT — it's regex-based, not a real parser")


class TestCCppAnalyzer(unittest.TestCase):
    def test_detects_dangerous_calls(self):
        profile = TargetDiscovery().discover(C_FIXTURE)
        analyzer = CCppStaticAnalyzer()
        findings = analyzer.run(profile, ScanConfig.for_profile("standard"))
        funcs_mentioned = {f.title for f in findings}
        self.assertTrue(any("strcpy" in t for t in funcs_mentioned))
        self.assertTrue(any("gets" in t for t in funcs_mentioned))
        self.assertTrue(any("system" in t for t in funcs_mentioned))

    def test_declared_capability_is_experimental(self):
        profile = TargetDiscovery().discover(C_FIXTURE)
        analyzer = CCppStaticAnalyzer()
        cap = analyzer.capability_for(profile)
        self.assertEqual(cap.level.value, "EXPERIMENTAL",
                          "C/C++ analyzer must be labeled EXPERIMENTAL, not claim full support")

    def test_confidence_is_deliberately_low(self):
        profile = TargetDiscovery().discover(C_FIXTURE)
        findings = CCppStaticAnalyzer().run(profile, ScanConfig.for_profile("standard"))
        for f in findings:
            self.assertLessEqual(f.confidence, 50)


class TestReportGenerators(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        orch = ScanOrchestrator()
        cls.result = orch.run_scan("report_test", PY_FIXTURE, ScanConfig.for_profile("standard"))

    def test_html_report_contains_key_sections(self):
        html_out = generate_html_report(self.result)
        for section in ["Executive Summary", "Target Profile", "Analysis Coverage",
                         "Findings (", "Limitations"]:
            self.assertIn(section, html_out)

    def test_html_report_never_claims_absolute_security_unqualified(self):
        # The Limitations section is allowed to say BlueLine "never asserts a
        # target is 100% secure" (a negation) — what must NEVER appear is an
        # unqualified affirmative claim of the form "is secure" / "is 100%
        # secure" without "not"/"never" governing it.
        html_out = generate_html_report(self.result)
        forbidden_affirmative = ["target is 100% secure.", "system is secure.", "is completely secure"]
        for phrase in forbidden_affirmative:
            self.assertNotIn(phrase, html_out.lower())

    def test_zero_findings_uses_honest_phrasing_not_a_security_guarantee(self):
        from copy import deepcopy
        empty_result = deepcopy(self.result)
        empty_result.findings = []
        html_out = generate_html_report(empty_result)
        self.assertIn("No confirmed findings were identified within the analyzed attack surface", html_out)

    def test_json_report_round_trips_findings_count(self):
        import json
        json_out = generate_json_report(self.result)
        data = json.loads(json_out)
        self.assertEqual(len(data["findings"]), len(self.result.findings))

    def test_sarif_report_is_valid_json_with_expected_shape(self):
        import json
        sarif_out = generate_sarif_report(self.result)
        data = json.loads(sarif_out)
        self.assertEqual(data["version"], "2.1.0")
        self.assertIn("runs", data)
        self.assertEqual(len(data["runs"][0]["results"]), len(self.result.findings))

    def test_csv_report_has_one_row_per_finding(self):
        csv_out = generate_csv_report(self.result)
        lines = [l for l in csv_out.strip().splitlines() if l]
        self.assertEqual(len(lines) - 1, len(self.result.findings))  # -1 for header


if __name__ == "__main__":
    unittest.main()
