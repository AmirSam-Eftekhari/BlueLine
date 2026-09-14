import unittest
from pathlib import Path

from app.analyzers.python_static import PythonStaticAnalyzer
from app.core.models import ScanConfig
from app.targets.discovery import TargetDiscovery

FIXTURE = str(Path(__file__).resolve().parent.parent / "test-targets" / "vulnerable-python")


class TestPythonStaticAnalyzer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = TargetDiscovery().discover(FIXTURE)
        cls.config = ScanConfig.for_profile("standard")
        cls.analyzer = PythonStaticAnalyzer()
        cls.findings = cls.analyzer.run(cls.profile, cls.config)
        cls.rules_found = {f.evidence[0].description.split()[1] for f in cls.findings if f.evidence}

    def test_applies_to_python_target(self):
        self.assertTrue(self.analyzer.applies_to(self.profile))

    def test_detects_expected_rule_classes(self):
        expected_rules = {
            "PY-HARDCODED-SECRET", "PY-OS-SYSTEM", "PY-SUBPROC-SHELL", "PY-YAML-UNSAFE",
            "PY-PICKLE-LOAD", "PY-WEAK-HASH", "PY-SQL-CONCAT", "PY-TEMP-INSECURE",
            "PY-TAR-TRAVERSAL", "PY-ASSERT-SECURITY", "PY-EVAL-EXEC", "PY-BROAD-EXCEPT",
            "PY-DEBUG-FLASK", "PY-BIND-ALL",
        }
        missing = expected_rules - self.rules_found
        self.assertEqual(missing, set(), f"Analyzer failed to detect: {missing}")

    def test_findings_have_exact_locations(self):
        for f in self.findings:
            self.assertIsNotNone(f.location)
            self.assertIn(":", f.location)
            file_part, _, line_part = f.location.rpartition(":")
            self.assertTrue(line_part.isdigit())

    def test_no_false_certainty(self):
        # Nothing from a static analyzer should ever claim CONFIRMED —
        # only dynamic/fuzz reproduction earns that status.
        for f in self.findings:
            self.assertNotEqual(f.validation_status.value, "CONFIRMED",
                                 f"{f.title} wrongly marked CONFIRMED by a static-only analyzer")

    def test_broken_file_does_not_crash_analyzer(self):
        import tempfile, os
        with tempfile.TemporaryDirectory() as tmp:
            bad_file = Path(tmp) / "broken.py"
            bad_file.write_text("def f(:\n  this is not valid python !!!")
            profile = TargetDiscovery().discover(tmp)
            findings = self.analyzer.run(profile, self.config)  # must not raise
            self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
