import unittest
from pathlib import Path

from app.analyzers.kotlin_static import KotlinStaticAnalyzer
from app.analyzers.scala_static import ScalaStaticAnalyzer
from app.analyzers.swift_static import SwiftStaticAnalyzer
from app.core.models import ScanConfig
from app.targets.discovery import TargetDiscovery

ROOT = Path(__file__).resolve().parent.parent / "test-targets"


class TestKotlinAnalyzer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = TargetDiscovery().discover(str(ROOT / "vulnerable-kotlin"))
        cls.findings = KotlinStaticAnalyzer().run(cls.profile, ScanConfig.for_profile("standard"))

    def test_applies_only_to_kotlin_targets(self):
        analyzer = KotlinStaticAnalyzer()
        self.assertTrue(analyzer.applies_to(self.profile))
        py_profile = TargetDiscovery().discover(str(ROOT / "vulnerable-python"))
        self.assertFalse(analyzer.applies_to(py_profile))

    def test_declared_capability_is_partial_not_full(self):
        cap = KotlinStaticAnalyzer().capability_for(self.profile)
        self.assertEqual(cap.level.value, "PARTIAL_SUPPORT")

    def test_detects_deserialization_and_weak_crypto(self):
        titles = {f.title for f in self.findings}
        self.assertTrue(any("ObjectInputStream" in t for t in titles))
        self.assertTrue(any("Weak cryptographic hash" in t for t in titles))
        self.assertTrue(any("Weak or insecure cipher" in t for t in titles))

    def test_broken_file_does_not_crash_analyzer(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "broken.kt"
            bad.write_bytes(b"\xff\xfe fun broken( {{{ not kotlin")
            profile = TargetDiscovery().discover(tmp)
            KotlinStaticAnalyzer().run(profile, ScanConfig.for_profile("standard"))  # must not raise


class TestSwiftAnalyzer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = TargetDiscovery().discover(str(ROOT / "vulnerable-swift"))
        cls.findings = SwiftStaticAnalyzer().run(cls.profile, ScanConfig.for_profile("standard"))

    def test_applies_only_to_swift_targets(self):
        self.assertTrue(SwiftStaticAnalyzer().applies_to(self.profile))

    def test_declared_capability_is_partial_not_full(self):
        cap = SwiftStaticAnalyzer().capability_for(self.profile)
        self.assertEqual(cap.level.value, "PARTIAL_SUPPORT")

    def test_detects_userdefaults_secret_and_force_unwrap(self):
        subcats = {f.subcategory for f in self.findings}
        self.assertIn("Insecure Local Storage", subcats)
        self.assertIn("Panic-based DoS", subcats)

    def test_broken_file_does_not_crash_analyzer(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "broken.swift"
            bad.write_bytes(b"\xff\xfe func broken( {{{ not swift")
            profile = TargetDiscovery().discover(tmp)
            SwiftStaticAnalyzer().run(profile, ScanConfig.for_profile("standard"))  # must not raise


class TestScalaAnalyzer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = TargetDiscovery().discover(str(ROOT / "vulnerable-scala"))
        cls.findings = ScalaStaticAnalyzer().run(cls.profile, ScanConfig.for_profile("standard"))

    def test_applies_only_to_scala_targets(self):
        self.assertTrue(ScalaStaticAnalyzer().applies_to(self.profile))

    def test_declared_capability_is_partial_not_full(self):
        cap = ScalaStaticAnalyzer().capability_for(self.profile)
        self.assertEqual(cap.level.value, "PARTIAL_SUPPORT")

    def test_detects_process_exec_and_deserialization(self):
        categories = {f.category for f in self.findings}
        self.assertIn("Injection", categories)
        self.assertIn("Insecure Deserialization", categories)

    def test_broken_file_does_not_crash_analyzer(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "broken.scala"
            bad.write_bytes(b"\xff\xfe object broken { {{{ not scala")
            profile = TargetDiscovery().discover(tmp)
            ScalaStaticAnalyzer().run(profile, ScanConfig.for_profile("standard"))  # must not raise


if __name__ == "__main__":
    unittest.main()
