import unittest
from pathlib import Path

from app.analyzers.go_static import GoStaticAnalyzer
from app.analyzers.java_static import JavaStaticAnalyzer
from app.core.models import ScanConfig
from app.targets.discovery import TargetDiscovery

JAVA_FIXTURE = str(Path(__file__).resolve().parent.parent / "test-targets" / "vulnerable-java")
GO_FIXTURE = str(Path(__file__).resolve().parent.parent / "test-targets" / "vulnerable-go")


class TestJavaAnalyzer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = TargetDiscovery().discover(JAVA_FIXTURE)
        cls.findings = JavaStaticAnalyzer().run(cls.profile, ScanConfig.for_profile("standard"))

    def test_applies_only_to_java_targets(self):
        analyzer = JavaStaticAnalyzer()
        self.assertTrue(analyzer.applies_to(self.profile))
        non_java_profile = TargetDiscovery().discover(
            str(Path(__file__).resolve().parent.parent / "test-targets" / "vulnerable-python"))
        self.assertFalse(analyzer.applies_to(non_java_profile))

    def test_declared_capability_is_partial_not_full(self):
        cap = JavaStaticAnalyzer().capability_for(self.profile)
        self.assertEqual(cap.level.value, "PARTIAL_SUPPORT")

    def test_detects_expected_categories(self):
        categories = {f.category for f in self.findings}
        self.assertIn("Injection", categories)
        self.assertIn("Insecure Deserialization", categories)
        self.assertIn("Cryptography", categories)
        self.assertIn("Credential Management", categories)

    def test_detects_runtime_exec_and_deserialization(self):
        titles = {f.title for f in self.findings}
        self.assertTrue(any("Runtime.exec" in t for t in titles))
        self.assertTrue(any("ObjectInputStream" in t for t in titles))

    def test_broken_file_does_not_crash_analyzer(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "Broken.java"
            bad.write_bytes(b"\xff\xfe not valid java {{{")
            profile = TargetDiscovery().discover(tmp)
            # Should not raise, even though this "Java" file is garbage.
            JavaStaticAnalyzer().run(profile, ScanConfig.for_profile("standard"))


class TestGoAnalyzer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = TargetDiscovery().discover(GO_FIXTURE)
        cls.findings = GoStaticAnalyzer().run(cls.profile, ScanConfig.for_profile("standard"))

    def test_applies_only_to_go_targets(self):
        analyzer = GoStaticAnalyzer()
        self.assertTrue(analyzer.applies_to(self.profile))

    def test_declared_capability_is_partial_not_full(self):
        cap = GoStaticAnalyzer().capability_for(self.profile)
        self.assertEqual(cap.level.value, "PARTIAL_SUPPORT")

    def test_detects_insecure_skip_verify(self):
        titles = {f.title for f in self.findings}
        self.assertTrue(any("InsecureSkipVerify" in t for t in titles))

    def test_detects_command_injection_risk(self):
        categories = {f.category for f in self.findings}
        self.assertIn("Injection", categories)

    def test_high_confidence_only_for_unambiguous_rule(self):
        # InsecureSkipVerify:true is unambiguous -> high confidence.
        # Import-only heuristics (math/rand, md5) are deliberately lower.
        for f in self.findings:
            if "InsecureSkipVerify" in f.title:
                self.assertGreaterEqual(f.confidence, 85)
            if "math/rand" in f.title or "md5" in f.title.lower():
                self.assertLessEqual(f.confidence, 50)


if __name__ == "__main__":
    unittest.main()
