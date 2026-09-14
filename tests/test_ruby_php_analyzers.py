import unittest
from pathlib import Path

from app.analyzers.php_static import PhpStaticAnalyzer
from app.analyzers.ruby_static import RubyStaticAnalyzer
from app.core.models import ScanConfig
from app.targets.discovery import TargetDiscovery

RUBY_FIXTURE = str(Path(__file__).resolve().parent.parent / "test-targets" / "vulnerable-ruby")
PHP_FIXTURE = str(Path(__file__).resolve().parent.parent / "test-targets" / "vulnerable-php")


class TestRubyAnalyzer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = TargetDiscovery().discover(RUBY_FIXTURE)
        cls.findings = RubyStaticAnalyzer().run(cls.profile, ScanConfig.for_profile("standard"))

    def test_applies_only_to_ruby_targets(self):
        analyzer = RubyStaticAnalyzer()
        self.assertTrue(analyzer.applies_to(self.profile))
        py_profile = TargetDiscovery().discover(
            str(Path(__file__).resolve().parent.parent / "test-targets" / "vulnerable-python"))
        self.assertFalse(analyzer.applies_to(py_profile))

    def test_declared_capability_is_partial_not_full(self):
        cap = RubyStaticAnalyzer().capability_for(self.profile)
        self.assertEqual(cap.level.value, "PARTIAL_SUPPORT")

    def test_detects_marshal_and_yaml_deserialization(self):
        titles = {f.title for f in self.findings}
        self.assertTrue(any("Marshal.load" in t for t in titles))
        self.assertTrue(any("YAML.load" in t for t in titles))

    def test_detects_command_injection_and_eval(self):
        categories = {f.category for f in self.findings}
        self.assertIn("Injection", categories)
        subcats = {f.subcategory for f in self.findings}
        self.assertIn("Code Injection", subcats)
        self.assertIn("Command Injection", subcats)

    def test_broken_file_does_not_crash_analyzer(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "broken.rb"
            bad.write_bytes(b"\xff\xfe def broken {{{ not ruby")
            profile = TargetDiscovery().discover(tmp)
            RubyStaticAnalyzer().run(profile, ScanConfig.for_profile("standard"))  # must not raise


class TestPhpAnalyzer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = TargetDiscovery().discover(PHP_FIXTURE)
        cls.findings = PhpStaticAnalyzer().run(cls.profile, ScanConfig.for_profile("standard"))

    def test_applies_only_to_php_targets(self):
        analyzer = PhpStaticAnalyzer()
        self.assertTrue(analyzer.applies_to(self.profile))

    def test_declared_capability_is_partial_not_full(self):
        cap = PhpStaticAnalyzer().capability_for(self.profile)
        self.assertEqual(cap.level.value, "PARTIAL_SUPPORT")

    def test_detects_lfi_and_object_injection(self):
        titles = {f.title for f in self.findings}
        self.assertTrue(any("File inclusion" in t for t in titles))
        self.assertTrue(any("unserialize" in t for t in titles))

    def test_lfi_is_flagged_critical(self):
        lfi = [f for f in self.findings if "File inclusion" in f.title]
        self.assertTrue(lfi)
        self.assertEqual(lfi[0].severity.value, "CRITICAL")

    def test_detects_sql_injection_from_request_input(self):
        sql_findings = [f for f in self.findings if f.subcategory == "SQL Injection"]
        self.assertTrue(sql_findings)
        self.assertEqual(sql_findings[0].severity.value, "CRITICAL")

    def test_broken_file_does_not_crash_analyzer(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "broken.php"
            bad.write_bytes(b"<?php $x = ; not valid php {{{")
            profile = TargetDiscovery().discover(tmp)
            PhpStaticAnalyzer().run(profile, ScanConfig.for_profile("standard"))  # must not raise


if __name__ == "__main__":
    unittest.main()
