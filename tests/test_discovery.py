import tempfile
import unittest
from pathlib import Path

from app.targets.discovery import TargetDiscovery
from tests.test_pe_parser import build_minimal_pe64


class TestTargetDiscovery(unittest.TestCase):
    def test_detects_dotexe_file_in_a_scanned_directory(self):
        # Regression: directory scanning only checked magic bytes on
        # extension-less files, so a Windows .exe sitting in a scanned
        # folder was never recognized as an executable at all — the most
        # common real-world case for that platform. Fixed in
        # TargetDiscovery._discover_directory; pinned here.
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "app.exe").write_bytes(build_minimal_pe64())
            (Path(tmp) / "readme.txt").write_text("hello")
            profile = TargetDiscovery().discover(tmp)
            self.assertIn("app.exe", profile.executables)

    def test_detects_dotdll_file_too(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "helper.dll").write_bytes(build_minimal_pe64())
            profile = TargetDiscovery().discover(tmp)
            self.assertIn("helper.dll", profile.executables)

    def test_does_not_misdetect_a_normal_dotexe_shaped_text_file(self):
        # A file merely named *.exe with no executable magic bytes must
        # not be flagged — extension alone isn't the signal, content is.
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "notes.exe").write_text("this is just text, not a real executable")
            profile = TargetDiscovery().discover(tmp)
            self.assertNotIn("notes.exe", profile.executables)

    def test_extensionless_elf_still_detected(self):
        # Don't regress the original (already-working) Linux/Mac case
        # while fixing the .exe case above.
        fixtures = Path(__file__).resolve().parent.parent / "test-targets" / "vulnerable-binaries"
        profile = TargetDiscovery().discover(str(fixtures))
        self.assertIn("normal_dynamic", profile.executables)

    def test_target_path_is_resolved_to_absolute(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = TargetDiscovery().discover(tmp)
            self.assertTrue(Path(profile.target_path).is_absolute())

    def test_nonexistent_path_reports_warning_not_a_crash(self):
        profile = TargetDiscovery().discover("/definitely/does/not/exist/anywhere")
        self.assertTrue(profile.discovery_warnings)


if __name__ == "__main__":
    unittest.main()
