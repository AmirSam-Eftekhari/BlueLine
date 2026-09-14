import unittest
from pathlib import Path

from app.analyzers.rust_static import RustStaticAnalyzer
from app.core.models import ScanConfig
from app.targets.discovery import TargetDiscovery

FIXTURE = str(Path(__file__).resolve().parent.parent / "test-targets" / "vulnerable-rust")


class TestRustAnalyzer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = TargetDiscovery().discover(FIXTURE)
        cls.findings = RustStaticAnalyzer().run(cls.profile, ScanConfig.for_profile("standard"))

    def test_applies_only_to_rust_targets(self):
        analyzer = RustStaticAnalyzer()
        self.assertTrue(analyzer.applies_to(self.profile))
        py_profile = TargetDiscovery().discover(
            str(Path(FIXTURE).parent / "vulnerable-python"))
        self.assertFalse(analyzer.applies_to(py_profile))

    def test_declared_capability_is_partial_not_full(self):
        cap = RustStaticAnalyzer().capability_for(self.profile)
        self.assertEqual(cap.level.value, "PARTIAL_SUPPORT")

    def test_detects_unsafe_blocks(self):
        unsafe_findings = [f for f in self.findings if f.subcategory == "Unsafe Escape"]
        self.assertEqual(len(unsafe_findings), 2)  # two planted unsafe blocks

    def test_detects_transmute_and_command_injection(self):
        titles = {f.title for f in self.findings}
        self.assertTrue(any("transmute" in t for t in titles))
        self.assertTrue(any("Command::new" in t for t in titles))

    def test_detects_hardcoded_secret_with_type_annotation(self):
        # Regression: Rust's `const NAME: &str = "value"` syntax was
        # initially missed because of the type annotation between the
        # name and the value — fixed in the regex, pinned here.
        secret_findings = [f for f in self.findings if f.subcategory == "Hardcoded Secret"]
        self.assertTrue(secret_findings)
        self.assertEqual(secret_findings[0].location, "main.rs:3")

    def test_broken_file_does_not_crash_analyzer(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "broken.rs"
            bad.write_bytes(b"\xff\xfe fn broken( {{{ not valid rust")
            profile = TargetDiscovery().discover(tmp)
            RustStaticAnalyzer().run(profile, ScanConfig.for_profile("standard"))  # must not raise


if __name__ == "__main__":
    unittest.main()
